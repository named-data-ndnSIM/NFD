/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2018,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "proactive-util.hpp"
#include "algorithm.hpp"
#include "common/logger.hpp"
#include "strategy.hpp"
#include "forwarder.hpp"

#include <ndn-cxx/lp/empty-value.hpp>
#include <ndn-cxx/lp/prefix-announcement-header.hpp>
#include <ndn-cxx/lp/tags.hpp>
#include <ndn-cxx/lp/util-header.hpp>

#include <boost/range/adaptor/reversed.hpp>

#include "ns3/ndnSIM/helper/ndn-fib-helper.hpp"
#include "ns3/ndnSIM/helper/ndn-stack-helper.hpp"

namespace nfd {
namespace fw {

NFD_REGISTER_STRATEGY(ProactiveUtil);

NFD_LOG_INIT(ProactiveUtil);

const time::milliseconds ProactiveUtil::RETX_SUPPRESSION_INITIAL(10);
const time::milliseconds ProactiveUtil::RETX_SUPPRESSION_MAX(250);

ProactiveUtil::ProactiveUtil(Forwarder& forwarder, const Name& name)
  : Strategy(forwarder)
  , ProcessNackTraits(this)
  , m_retxSuppression(RETX_SUPPRESSION_INITIAL,
                      RetxSuppressionExponential::DEFAULT_MULTIPLIER,
                      RETX_SUPPRESSION_MAX)
{
  ParsedInstanceName parsed = parseInstanceName(name);
  if (!parsed.parameters.empty()) {
    BOOST_THROW_EXCEPTION(std::invalid_argument("ProactiveUtil does not accept parameters"));
  }
  if (parsed.version && *parsed.version != getStrategyName()[-1].toVersion()) {
    BOOST_THROW_EXCEPTION(std::invalid_argument(
      "ProactiveUtil does not support version " + to_string(*parsed.version)));
  }
  this->setInstanceName(makeInstanceName(name, getStrategyName()));
}

const Name&
ProactiveUtil::getStrategyName()
{
  static Name strategyName("/localhost/nfd/strategy/proactive-util/%FD%01");
  return strategyName;
}

void
ProactiveUtil::afterReceiveInterest(const  FaceEndpoint& ingress, const Interest& interest,
                                    const shared_ptr<pit::Entry>& pitEntry)
{
  if (interest.getTag<lp::HopLimitTag>() == nullptr) {
      // regular interest
      processRegularInterest(ingress.face, interest, pitEntry);
  }
  else {
    // util Interest
    processUtilInterest(ingress.face, interest, pitEntry);
  }
}

void
ProactiveUtil::afterReceiveNack(const FaceEndpoint& ingress, const lp::Nack& nack,
                                    const shared_ptr<pit::Entry>& pitEntry)
{
  this->processNack(ingress.face, nack, pitEntry);
}

void
ProactiveUtil::broadcastInterest(const Interest& interest, const FaceEndpoint& ingress,
                                        const shared_ptr<pit::Entry>& pitEntry)
{
  const Face& inFace = ingress.face;
  for (auto& outFace : this->getFaceTable() | boost::adaptors::reversed) {
    if ((outFace.getId() == inFace.getId() && outFace.getLinkType() != ndn::nfd::LINK_TYPE_AD_HOC) ||
        wouldViolateScope(inFace, interest, outFace) || outFace.getScope() == ndn::nfd::FACE_SCOPE_LOCAL) {
      continue;
    }
    this->sendInterest(pitEntry,FaceEndpoint(outFace, 0), interest);
    //pitEntry->getOutRecord(outFace)->insertStrategyInfo<OutRecordInfo>().first->isNonDiscoveryInterest = false;
    NFD_LOG_DEBUG("send Util Interest=" << interest << " from="
                  << inFace.getId() << " to=" << outFace.getId());
  }
}

void
ProactiveUtil::processRegularInterest(const Face& inFace, const Interest& interest,
                                      const shared_ptr<pit::Entry>& pitEntry)
{
 // const Face& inFace = ingress.face;
  const fib::Entry& fibEntry = this->lookupFib(*pitEntry);
  for (const auto& nexthop : fibEntry.getNextHops()) {
     Face& outFace = nexthop.getFace();
    if (!wouldViolateScope(inFace, interest, outFace) &&
        canForwardToLegacy(*pitEntry, outFace)) {
      NFD_LOG_DEBUG("send regular Interest=" << interest << " from="
                     << inFace.getId() << " to=" << outFace.getId());
      this->sendInterest(pitEntry, FaceEndpoint(outFace, 0), interest);
      return;
    }
  }
}

void
ProactiveUtil::processUtilInterest(const Face& inFace, const Interest& interest,
                                   const shared_ptr<pit::Entry>& pitEntry)
{
 // const Face& inFace = ingress.face;
  Name interestName = interest.getName();
  if (interestName.size() <= 1) {
    NFD_LOG_WARN("Util Interest with no services of utilization received");
    return;
  }

  for (uint8_t i = 1; i < interestName.size() - 1; i++) {

    Name serviceName = Name(interestName.get(i).toUri());
    // already have this service name, check inFace
    fib::Entry* fibEntry = m_forwarder.getFib().findExactMatch(serviceName);
    if (fibEntry->getNextHops().empty()) {
      ns3::ndn::FibHelper::AddRoute(m_forwarder.m_node, serviceName, inFace.getId(), std::stoi(interestName.get(-1).toUri()));
    }
    else {
      bool found = false;
      for (const auto& nexthop : fibEntry->getNextHops()) {
        Face& outFace = nexthop.getFace();
        if (outFace.getId() == inFace.getId()) {
          found = true;
         // uint64_t endpointId = nexthop.getEndpointId();
         // fibEntry->findNextHop(inFace, endpointId)->setCost(std::stoi(interestName.get(-1).toUri()));
          fibEntry->findNextHop(inFace);
	  fibEntry->sortNextHops();
        }
      }
      if (!found)
        ns3::ndn::FibHelper::AddRoute(m_forwarder.m_node, serviceName, inFace.getId(), std::stoi(interestName.get(-1).toUri()));
    }
  }

  if (uint64_t(*interest.getTag<lp::HopLimitTag>()) == 0) {
    // interest to be discarded
    NFD_LOG_WARN("Util Interest with 0 hop limit. Will be discarded..");
    return;
  }

  broadcastInterest(interest, FaceEndpoint(inFace,0), pitEntry);
}

} // namespace fw
} // namespace nfd

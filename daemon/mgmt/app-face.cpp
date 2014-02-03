/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (C) 2014 Named Data Networking Project
 * See COPYING for copyright and distribution information.
 */

#include "app-face.hpp"

namespace nfd {

void
AppFace::sign(Data& data)
{
  m_keyChain.sign(data);
}

} // namespace nfd

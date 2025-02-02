/*
 * Copyright (c) 2017-2018 ARM Limited
 * All rights reserved
 *
 * The license below extends only to copyright in the software and shall
 * not be construed as granting a license to any other intellectual
 * property including but not limited to intellectual property relating
 * to a hardware implementation of the functionality of the software
 * licensed hereunder.  You may use the software subject to the license
 * terms below provided that you ensure that this notice is replicated
 * unmodified and in its entirety in all distributions of the software,
 * modified or unmodified, in source code or in binary form.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors: Andrew Bardsley
 */

#ifndef __CPU_UTILS_HH__
#define __CPU_UTILS_HH__

#include "base/types.hh"

/** Returns the offset of `addr` into an aligned block of size `block_size` */
inline Addr
addrBlockOffset(Addr addr, Addr block_size)
{
    return addr & (block_size - 1);
}

/** Returns the address of the aligned block of size `block_size` closest to
 *  `addr` */
inline Addr
addrBlockAlign(Addr addr, Addr block_size)
{
    return addr & ~(block_size - 1);
}

/** Returns true if the given [`addr` .. `addr`+`size`-1] transfer needs to be
 *  fragmented across a block size of `block_size` */
inline bool
transferNeedsBurst(Addr addr, unsigned int size, unsigned int block_size)
{
    return (addrBlockOffset(addr, block_size) + size) > block_size;
}

/**
 * Test if there is any active element in an enablement range
 */
inline bool
isAnyActiveElement(const std::vector<bool>::const_iterator& it_start,
                   const std::vector<bool>::const_iterator& it_end)
{
    auto it_tmp = it_start;
    for (;it_tmp != it_end && !(*it_tmp); ++it_tmp);
    return (it_tmp != it_end);
}

/**
 * Test if all elements are active in an enablement range
 */
inline bool
isAllActiveElement(const std::vector<bool>::const_iterator& it_start,
                   const std::vector<bool>::const_iterator& it_end)
{
    auto it_tmp = it_start;
    for (;it_tmp != it_end && (*it_tmp); ++it_tmp);
    return (it_tmp == it_end);
}

#endif // __CPU_UTILS_HH__

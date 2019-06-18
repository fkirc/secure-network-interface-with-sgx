#pragma once

// This file must comply with special rules and restrictions of the edl language because it is included in the edl file of this library.
// This file is shared between the trusted lib and the support lib.

struct trusted_sock_addr {
    unsigned int ip4_addr;
    unsigned short port;
};


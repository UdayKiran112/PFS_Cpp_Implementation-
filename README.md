# VANET Implementation using MIRACL Core Library

## Overview

This project implements a basic Vehicular Ad-hoc Network (VANET) simulation using the [MIRACL Core](https://github.com/miracl/core) library. VANETs are a form of Mobile Ad-hoc Network (MANET) that provide communication between vehicles and roadside units, enhancing traffic safety and efficiency.

The MIRACL Core library is used for cryptographic operations within the network, ensuring secure communication among vehicles.

## Features

- **Secure Communication:** Ensures end-to-end encryption between vehicles using public key cryptography.
- **Efficient Key Management:** Utilizes MIRACL Core's elliptic curve cryptography (ECC) for efficient key generation and management.
- **Scalability:** Designed to handle a large number of nodes (vehicles) in the network.
- **Simulation Environment:** Simulates vehicular movement and communication in a controlled environment.

## Prerequisites

Before you begin, ensure you have met the following requirements:

- **C++ Compiler**: GCC, Clang, or any C++11 compatible compiler.
- **CMake**: Version 3.0 or higher.
- **MIRACL Core Library**: Download and install the [MIRACL Core library](https://github.com/miracl/core).

### Installing MIRACL Core

Clone the MIRACL Core repository and follow the installation instructions provided in their [documentation](https://github.com/miracl/core/blob/master/README.md).

```bash
git clone https://github.com/miracl/core.git
cd core
mkdir build && cd build
cmake ..
make

# VANET Implementation Using MIRACL Core Library

## Overview

This project implements a basic Vehicular Ad-hoc Network (VANET) simulation using the [MIRACL Core](https://github.com/miracl/core) library. VANETs are a type of Mobile Ad-hoc Network (MANET) that enable communication between vehicles and roadside units, enhancing traffic safety and efficiency.

The MIRACL Core library is used for cryptographic operations within the network, ensuring secure communication among vehicles.

## Features

- **Secure Communication:** Provides end-to-end encryption between vehicles using public key cryptography.
- **Efficient Key Management:** Utilizes MIRACL Core's elliptic curve cryptography (ECC) for effective key generation and management.
- **Scalability:** Capable of handling a large number of nodes (vehicles) within the network.
- **Simulation Environment:** Simulates vehicular movement and communication in a controlled setting.

## Prerequisites

Ensure you have the following before starting:

- **C++ Compiler:** GCC, Clang, or any C++11 compatible compiler.
- **CMake:** Version 3.0 or higher.
- **MIRACL Core Library:** Download and install the [MIRACL Core library](https://github.com/miracl/core).

### Installing MIRACL Core

To install the MIRACL Core library, follow these steps:

1. Clone the MIRACL Core repository:

    ```bash
    git clone https://github.com/miracl/core.git
    ```

2. Navigate to the repository directory and create a build directory:

    ```bash
    cd core
    mkdir build && cd build
    ```

3. Run CMake to configure the project:

    ```bash
    cmake ..
    ```

4. Build the library:

    ```bash
    make
    ```

5. Optionally, install the library:

    ```bash
    sudo make install
    ```

## Building the Project

To build the VANET project, ensure the MIRACL Core library is correctly installed and follow these steps:

1. Navigate to the project's root directory:

    ```bash
    cd path/to/your/project
    ```

2. Create a build directory:

    ```bash
    mkdir build && cd build
    ```

3. Run CMake to configure the project:

    ```bash
    cmake ..
    ```

4. Build the project:

    ```bash
    make
    ```

5. Run the application:

    ```bash
    ./bin/app
    ```

## Usage

After building, you can run the application to simulate vehicular communication and observe secure communication using the MIRACL Core library.

## Contributing

If you wish to contribute to this project, please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the [MIT License](LICENSE).

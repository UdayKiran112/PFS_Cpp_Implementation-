# Project Issues and Implementation Guide

This document provides a summary of the current issues and tasks that need to be addressed in various `.cpp` files. The tasks include function modifications, completion of to-dos, and code reviews. Follow the instructions below to implement the required changes.

## Files Overview

### `TA.cpp`

1. **`signatureGeneration` Function**
   - **Required Changes**:
     - Remove the `cpsrng` generator from this function.
     - Make `cpsrng` an input parameter to the function, as it is generated in the `main` function.
     - Multiply the hash value by the random number `a` as per the specified cryptographic equation.

2. **`checkRegValid` Function**
   - **To-Do**:
     - Complete the implementation of this function.

3. **`Validaterequest` Function**
   - **Input Changes**:
     - Update the input parameters of the signature function as required by the new design.

### `Vehicle.cpp`

1. **`signMessage` Function**
   - **Review Required**:
     - The implementation does not match the blueprint. Review and update the function to match the given specifications.

2. **`sendingMessage` Function**
   - **Review Required**:
     - The implementation does not match the blueprint. Review and update the function to match the given specifications.

### `Key.cpp` and `Message.cpp`

- **Status**: No issues or changes have been identified in these files at the moment.

## Setup and Build Instructions

### Prerequisites
- Make sure to install the necessary dependencies, including the Miracl core library.
- Ensure your environment is properly configured to compile C++ code.

### Compilation
The project can be compiled using the provided `Makefile`. This `Makefile` supports both Linux and Windows environments.

```bash
# On Linux
make

# On Windows
make win

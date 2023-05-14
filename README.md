# Secure Maritime Messaging Protocol (SMMP)

SMMP is a secure messaging protocol implemented in Python. It uses the PyCryptodome library to provide cryptographic operations such as symmetric and public-key cryptography, and digital signatures. The library consists of the following programs:

1. `smmp.py`: Contains the core functionalities of the protocol
2. `app.py`: Provides a user interface to access agent functionalities and SMMP functionalities
3. `agent.py`: Provides agent functionalities, such as sending and receiving messages, and subscribing to subjects
4. `edge_router.py`: Provides edge router functionalities, such as managing agent connections, message queue, and handling subscriptions

The source files for the library are located in the `src/library` directory. The test files are located in the `src` directory and include the following:

1. `unit_test.py`: Unit tests for 'smmp.py'
2. `performance_test.py`: Performance tests for encryption + digital signature and decryption + signature verification
3. `pgp_performance_test.py`: Similar test to 'performance_test.py', except it uses OpenPGP standard and RSA
4. `correctness_test.py`: Correctness tests for 'smmp.py'
5. `robustness_test.py`: Robustness tests for 'smmp.py'

## Installation

In order to run the programs and tests, you need to install the PyCryptodome and PGPy libraries. To do this, enter the following commands in the terminal:

```bash
pip install pycryptodome
pip install pgpy
```

## Running the interface

Once you have installed the required libraries, you can run the interface by executing the `app.py` file, located in the `src/library` directory.

1. Open two separate terminal windows
2. In the first terminal, navigate to the `src/library` directory and run the `app.py` file:

```bash
python3 app.py
```

This command will run the interface, and the interface will provide the app and SMMP functionalities. 

3. In the second terminal, navigate to the `src/library` directory and run the `edge_router.py` file:

```bash
python3 edge_router.py
```

This command will run the edge router which will then listen for incoming connections. You can run 'app.py' several times and connect them all to the same edge router process.

## Running the tests

To run the tests, navigate to the `src` directory and execute the desired test file using Python:

```bash
python3 <test_file.py>
```

Replace `<test_file.py>` with the name of the test file you want to run.

## Usage

With the `app.py` file running, you can access the available commands by typing `help` in the command line. This will display a list of available commands and their descriptions. You can use these commands to access agent functionalities.

Remember to always run the `edge_router.py` file in order to ensure proper communication between the agent and edge router.

For more information on the specific functions, refer to the docstrings provided in the `smmp.py`, `app.py`, `agent.py`, and `edge_router` files.

## Customizing the number of iterations for performance tests

In the performance tests (`performance_test.py` and `pgp_performance_test.py`), you can change the number of iterations in the code if you want to try more iterations. Be aware that increasing the number of iterations can result in quite long test execution times.

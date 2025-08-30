# Project: P7-SmartNIC

## Overview
P7-SmartNIC is a project focused on leveraging SmartNIC technology to enhance network performance and offload processing tasks. This repository contains the source code, documentation, and resources for the project.

## Features
- High-performance network processing
- Offloading computational tasks to SmartNICs
- Scalable and modular design

## Getting Started
### Prerequisites
You need the DOCA environment running on a BlueField-2 SmartNIC. Ensure that the DOCA SDK is properly installed and configured on your SmartNIC. Refer to the official NVIDIA documentation for setup instructions.

You need to install the dependencies listed in the `requirements.txt` file. Run the following command:

```bash
pip install -r requirements.txt
```

### Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/lopesvictor1/p7-smartnic.git
    ```
2. Navigate to the project directory:
    ```bash
    cd p7-smartnic
    ```
3. Restart Environment
   To restart the environment, run the following script provided in the repository:

    ```bash
    ./scripts/restart_environment.sh
    ```

    Ensure that you have the necessary permissions to execute the script. If not, you may need to grant execute permissions:

    ```bash
    chmod +x ./scripts/restart_environment.sh
    ```

### Usage
To run the code, use the following command:

```bash
python3 create_topology.py --sw X
```

Replace `X` with the number of switches in the linear topology you want to create.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch:
    ```bash
    git checkout -b feature-name
    ```
3. Commit your changes:
    ```bash
    git commit -m "Description of changes"
    ```
4. Push to your branch:
    ```bash
    git push origin feature-name
    ```
5. Open a pull request.



## Contact
For questions or support, please contact victorlopesvictor@gmail.com.

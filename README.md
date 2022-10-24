# ESP32-Bluetooth-Obex  
This project aims to provide file-sharing capabilities between the ESP32 Bluetooth and any Android/Linux device over their default OBEX protocols, something currently missing from the bluedroid stack bundled with the esp-idf. This can also be used as a starting point/example for anyone trying to write custom Bluetooth protocols.  
  
# Usage  
To run the code you would need an ESP32 board and ESP-IDF installed on your computer. (Steps listed for Linux systems)  
## Project Configuration
1. Run "$ idf.py set-target esp32" (or any other esp32 model) to set the MCU type.
2. Run "$ idf.py menuconfig" in the project folder after cloning the repo, this would open the config menu. Navigate to Component Config --> Bluetooth, enable the Bluetooth option and from here navigate to Bluetooth controller --> Bluetooth controller mode --> BR/EDR Only. In the Bluetooth controller options select HCI mode and set it to VHCI. Select Controller only in the Bluetooth host menu and press S to save your config.   
3. Run "$ idf.py build" to compile and link the source files.  
4. Plug in the ESP32 board and run "$ idf.py flash" to upload the generated binary to the microcontroller.  
5. Optionally run "$ idf.py monitor" to view the serial output.   
6. From your Android/Linux device connect to "BT-ADV", enter the auth pin "1234" (configurable in the code) and start sending a file. The file will be received by the controller. Note that the handling of the received file has to be implemented according to your needs. Currently the file name is printed on the stdout and the file contents are summed.  

The process above has been tested using a Ubuntu 20.04LTS system on an ESP32-WROOM-32 devkit with ESP-IDF v4.3.3-dirty.
Currently only recieving a file is supported

Lastly, this project is still under active development and several known bugs are gradually being patched. I would appreciate any feedback/suggestion so feel free to open an issue or contact me directly via email (pranjalkushwaha@cse.iitb.ac.in) for any discussion.

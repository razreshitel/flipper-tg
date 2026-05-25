#!/bin/bash
sudo openssl req -x509 -newkey rsa:2048 -keyout /home/pi/flipper-tg/key.pem -out /home/pi/flipper-tg/cert.pem -days 3650 -nodes -subj "/CN=192.168.0.102"

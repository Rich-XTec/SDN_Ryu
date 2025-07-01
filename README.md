SDN project with RYU on ubuntu

The objective of this project is to run a virtual switch on linux using mininet to test connections and make and app like a firewall to catch and block packages between IP.

### Step by Step how to have the project working

1 First you need to download the VM image from the link: 
  https://github.com/mininet/mininet/releases/
  1. Download the image ubuntu-20.04.1

2 Open the image on your VM run it
  1. Login: mininet
  2. Password: mininet

3 On the terminal inside the VM type this commands:
```
  sudo apt update

  sudo apt install software-properties-common -y

  sudo add-apt-repository ppa:deadsnakes/ppa -y

  sudo apt install python3.8

  sudo pip install eventlet==0.30.2

```
now you will have mininet with the correct pythohn version installed.

4 To install Ryu:
```
 sudo pip3 install ryu

```
5 You can run a pre-built test of ryu with:
```
 sudo mn --controller ryu

```
Or You can also specify the Ryu application on the mn command line:
```
  sudo mn --controller,ryu.app.simple_switch_13
  # simple_switch_13 is your app name
```

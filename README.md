# vpn-up-for-openconnect
VPN Up for OpenConnect

### Features ###

A shell script for openconnect which allows:</br>
- to define multiple VPN connections</br>
- to run openconnect without entering the username and password</br>
- to run in the background</br>
- to authenticate with a certiftcate

### Sample configuration section ###
```
BACKGROUND=true   # If you don't want to run in background, so make this false

# Company VPN
export COM_NAME="My Company VPN"
export COM_HOST=vpn.mycompany.com
export COM_AUTHGROUP=developers
export COM_USER=sorin.ipate
export COM_PASSWD="MyPassword"
export COM_SERVER_CERTIFICATE="SHA1-OtherCharachters"     # If you don't have server certificate so don't fill this
```

### Run VPN Up ###

1. Please make sure you have `openconnect` installed before moving on. Follow the instructions [here](https://formulae.brew.sh/formula/openconnect).
2. [Download the latest release](https://github.com/amindadgar/vpn-up-for-openconnect/releases/download/v1.1-alpha/vpn-up-for-openconnect-main.zip).
3. Copy the `vpn-up.command` file to the `bin` folder.
4. Update the `vpn-up.command` file with the appropiate VPN connection information as shown above.
5. Make an alias `alias vpn-up='~/bin/vpn-up.command'` in `bash` or `zsh` shell. Follow the instructions [here](https://wpbeaches.com/make-an-alias-in-bash-or-zsh-shell-in-macos-with-terminal/?__cf_chl_jschl_tk__=60015f4af93b104457efe3f2c7cd70de60ea05aa-1620807543-0-Ab8kPRiPbnWqJwPgGZ3k9zQ7t6ZrVnGiWZZGwLH1zmtS0Z2_I9_4k3484HAUDxe0WrYTgXZcYJg86SM895qayJYySOYhh0XdTBtOZwfa-KKLrgR-KJ9rvQmIas6UVdqHdedjUmCgljtFoxzGKguvu1TZ0NA_WAt8FrrfYo8aYhaXFXFVPkhvarI2mI1vWHc06ROepAwLTHfibEXn6VIiC02c0s3RD_5h_NsByw_6eWHESbqdUTnahAA-ls6lgQ7wY556EShckoVIvPGgnLWlYb4diIXOKntvTKMrPAtndHnB1oGY9RC8tZlfDlRrdnB4d6aaKgyp1uKgL77BPmmuRP9TDI3cnqGJoKc9_-Og5t5H2mOPjgo7La9F6Nja6Pn6jnyExLDsYvoASWdOG6mlYdP8IVQ9MXKJcoYphsdiZNuv4WxieW9GY7rPIdMQ0y2Rq9Rae04fi0JFl7GdQKEbC0uEY5umB5Bd9Dsc1aY6xb85).
6. Run `vpn-up` to start and voilà.

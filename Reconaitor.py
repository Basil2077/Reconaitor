import ipaddress, pyfiglet, re, socket, threading, time, requests, json, sys
from netaddr import *
from colorama import Fore
import art
global website_url
#Artistic Information
artpost = art.text2art("Reconaitor")
def info():
    print(Fore.RED,' Created By:  ---> Basil Abdulrahman')

    print(Fore.LIGHTBLACK_EX,'Version 1.0')
# re
ip_add_pattern = re.compile("^(?:[0-9]{1,3}.){3}[0-9]{1,3}$")
re.compile("^(?:[0-9]{1,3}.){3}[0-9]{1,3}$")
re.compile("^(?:[0-9]{1,3}.){3}[0-9]{1,3}$")
checkurl= "^((?!-)[A-Za-z0-9-]" +"{1,63}(?<!-)\\.)" +"+[A-Za-z]{2,6}"
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
global ports
ports=[]

# method that scans web for a website's information
def ScanWeb(ip):
    while True:
        print("please enter the range of ports to scan. ex: 30-60 ")
        port_range = input("enter port range: ")
        print("scanning ports..")
        time.sleep(1)
        # line 155 will remove any additional spaces
        port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
        # Port validation
        if port_range_valid:
            # if the range is valid we will split the 2 ranges so we can add them in the port list
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            port = [port_min, port_max]

        break
    ScanPort(ip, port_min, port_max)
    try:
        
        #requests website data
        req = requests.get("https://ipinfo.io/" + ip + "/json")
        #transfers requested data into a dictionary
        data = json.loads(req.text)
        print("connecting to server..")
        time.sleep(0.6)
        print("connected")
        print("retriving data.. \n")
        time.sleep(2)
        # prints the available data

        if data["ip"]:
            print("IP:", data["ip"])
        try:
            if data["hostname"]:
                print("Hostname:", data["hostname"])
        except:
            pass
        if data["city"]:
            print("City:", data["city"])
        if data["region"]:
            print("Region:", data["region"])
        if data["country"]:
            print("Country:", data["country"])
        if data["loc"]:
            print("Geo location address:", data["loc"])
        if data["org"]:
            print("Organization:", data["org"])
        if data["timezone"]:
            print("Timezone:", data["timezone"])
        print("\nwould you like to print the results in a file?")
        print("1: yes")
        print("2: no")

        while True:
            filec = input("--:")
            if filec == "1":
                break

            elif filec == "2":
                break
            else:
                print("Wrong input")
        # if user chooses 1: we will print the information on a file in a directory he chooses.
        if filec == "1":
           # print("Where would you like to save the file? (enter file directory)")
            #direc = input("--:")
            #print(direc)
            localwebservices_file = open('C:\\Users\HP\PycharmProjects\CYS403Project\Reconaitor Files\\reconaitor.txt', "w+")
            localwebservices_file.write('Results for: ' + website_url + '\n')
            if data["ip"]:
                localwebservices_file.write(f'IP: {data["ip"]}\n')
            try:
                if data["hostname"]:
                    localwebservices_file.write(f'Hostname: {data["hostname"]}\n')
            except:
                pass
            if data["city"]:
                localwebservices_file.write(f'City: {data["city"]}\n')
            if data["region"]:
                localwebservices_file.write(f'Region: {data["region"]}\n')
            if data["country"]:
                localwebservices_file.write(f'Country: {data["country"]}\n')
            if data["loc"]:
                localwebservices_file.write(f'Geo location address: {data["loc"]}\n')
            if data["org"]:
                localwebservices_file.write(f'Organization: {data["org"]}\n')
            if data["timezone"]:
                localwebservices_file.write(f'Timezone: {data["timezone"]}\n')
            print("Data has been written successfuly!")

    except Exception as ex:
        print("Exception: " + str(ex))

    finally:
        print("Terminating...")
        time.sleep(1)

    # webservices_file.write(f"data is {data}")



# scan ports
def PortScan(ip, portnum):
    try:
        #create a new ipv4 socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as object:
            #check ip and port connection
            object.connect((ip, portnum))
            #appends open ports
            ports.append(portnum)


    except Exception as E:
        pass


def ScanPort(ip, Startport, endPort):
    try:
        # port_file = open("port.txt", "a")
        # port_file.write(f"opened port for address {ip_add_entered} \n")
        # print(type(endPort))
        for i in range(Startport, endPort + 1):
            #each iteration we will create a new thread that will be sent to the port scan method
            t = threading.Thread(target=PortScan, args=(ip, i))
            #thread starting point
            t.start()
        if ports:
            print(ports)
        else:
            print("There are no open ports in that range!")
            sys.exit(0)

        if (str(ip_add_entered).startswith("192") | str(ip_add_entered).startswith("127") | str(
                ip_add_entered).startswith("10")):
            # port_file.write(f"scanning ports {ports}...\n")
            for i in ports:
                print("Port ", i, " is opened ")
                # port_file.write(f"port {i} is opened\n")
                socket.getservbyport(i)
            # print results in a file
            print("\n")
            print("\nwould you like to print the results in a file?")
            print("1: yes")
            print("2: no")
            while True:
                filec = input("--:")
                if filec == "1":
                    break

                elif filec == "2":
                    break
                else:
                    print("Wrong input")
            if filec == "1":
                #print("Where would you like to save the file? (enter file directory)")
                #direc = input("--:")
                localwebservices_file = open('C:\\Users\HP\PycharmProjects\CYS403Project\Reconaitor Files\\reconaitor.txt', "w")
                for i in ports:
                    localwebservices_file.write(f'Port , {i}, is opened \n')
                    # port_file.write(f"port {i} is opened\n")
                    socket.getservbyport(i)
                print("Data has been written successfuly!")

    except Exception as ex:
        print("Exception: " + str(ex))

    finally:
        print("Terminating...")
        time.sleep(1)


# main
print(Fore.RED, artpost)
info()
print(Fore.LIGHTGREEN_EX)
print("What would you like to scan?")
print("1: Website")
print("2: Ports")
while True:
    choice = input("--: ")
    if choice == "1":
        break

    elif choice == "2":
        break
    else:
        print("Wrong input")

while True:

    # ip_add_entered=input("\nPlease enter your ip address: ")
    try:

        if choice == "1":
            ip_add_entered = input("\nPlease enter website URL: ")
            website_url = ip_add_entered
            print("checking URL")
            ip_add_entered = socket.gethostbyname(ip_add_entered)

            if ipaddress.ip_address(ip_add_entered) and not IPAddress(ip_add_entered).is_private():
                print(ip_add_entered, "is valid ")
                break
            else:
                print("The URL address is wrong, please try again!")
        elif choice == "2":
            ip_add_entered = input("\nPlease enter a local ip address: ")
            if ipaddress.ip_address(ip_add_entered) and IPAddress(ip_add_entered).is_private():
                print(ip_add_entered, "is valid ")
                break
            else:
                print("The IP address is wrong, please try again!")

    except Exception as ex:
        print("The IP address is wrong, please try again!")

    # if ip_add_pattern.search(ip_add_entered):

if (choice == "1"):
    try:

        ScanWeb(ip_add_entered)
    except Exception:
        print("Some error occurred while scanning")

    # if (str(ip_add_entered).startswith("192")| str(ip_add_entered).startswith("127")| str(ip_add_entered).startswith("10")):


elif choice == "2":
    while True:
        print("please enter the range of ports to scan. ex: 30-60 ")
        port_range = input("enter port range: ")
        print("scanning ports..")
        time.sleep(1)
        # line 155 will remove any additional spaces
        port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
        # Port validation
        if port_range_valid:
            # if the range is valid we will split the 2 ranges so we can add them in the port list
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            port = [port_min, port_max]

        break
    ScanPort(ip_add_entered, port_min, port_max)
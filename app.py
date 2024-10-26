from flask import Flask, render_template, request
import nmap
import subprocess #con subprocess podemos ejecutar comandos externos al codigo, como ping.


#empieza la aplicacion de flask
app = Flask(__name__)

#en esta lista guardamos las ips que se encuentran al primer escaneo.
listaDeIps = []

#como estoy en widnows, -n es propio de windows y es para indicar cuantos paquetes
#vamos a enviar, y el 1 es para pasarselo al n, es decir enviaremos un solo paquete a la ip.
def ping_ip(ip):
    command = ["ping", "-n", "1", ip]
    #enseguida, corremos el "comando" que estamos construyendo en la linea anterior, que 
    #consiste en el ping hacia las ips que iremos probando.

    #stoud almacena la salida del comando y stderr captura la salida del error si hubo fallo
    response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return response.returncode == 0 

    #el atributo returncode es parte de los Completedprocess, que es propio
    #de subprocess. Si el returncode es cero, indica que el comando se corrio
    #con éxito.
    

#Formateamos la direccion ip,
def convertirIpEntero(ip):
    return int(''.join([f"{int(octeto):03}" for octeto in ip.split('.')]))

#el / indica el index de la aplicación. Usamos GET porque es parte del protocolo HTTP.
#entonces cuando el usuario entra al enlace, se hace una petición GET , y cuando se envian
#datos de un formulario, se hace una solicitud POST.

#Estamos definiendo que nuestra aplicación recibe tanto una petición GET o POST.
@app.route('/', methods=['GET', 'POST'])
def index():
    global listaDeIps 
    limite = 20  
    
    if request.method == 'POST': #cuando ingresamos un valor en el input, se cumple esto
        #pues usamos el metodo POST.
        listaDeIps = [] #reiniciamos la lista
        
        #del form, tomamos lo que se introdujo en el input y lo separamos, el parametro
        #1 indica que comenzamos a separar de derecha a izquierda a partir del primer punto.
        #Asi tomamos los primeros 3 octetos y lo concatenamos con .0/21, que corresponde a
        #la mascara de red. Esto lo guardamos en nuestra variable nm y empezamos a scanear.
        gateway = request.form['gateway']
        subnet = gateway.rsplit('.', 1)[0] + '.0/21'  
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments='-sn')

        #Filtramos solo las IPs activas y guardamos en listaDeIps
        for host in nm.all_hosts():
            if ping_ip(host): #si nuestro returncode es 0, es decir TRUE,
                listaDeIps.append((host, 'ACTIVA'))  #agregamos nomas las activas, concatenamos 
            
            #detener este ciclo cuando ya lleguemos al tope
            if len(listaDeIps) >= limite:
                break
        
        #usamos sort para ordenar las ips.
        listaDeIps.sort(key=lambda x: convertirIpEntero(x[0]))

        print("PRIMER ESCANEO LISTO: Ips activas encontradas: ", listaDeIps)  # Verifica en la consola


    #SI NO ES POST el metodo, por ende será GET, entonces reiniciaremos la lista.
    # En cada recarga (GET), hacemos ping a las IPs activas encontradas
    hosts = []
    for ip in listaDeIps:
        estado = 'ACTIVA' if ping_ip(ip[0]) else 'INACTIVA'  # Hacemos ping a cada IP, 
        #si al hacer ping devuelve TRUE (o el cero de returncode,) el estado se pone como
        #ACTIVA.
        hosts.append((ip[0], estado)) 
        print(f"Ping a {ip[0]}: {estado}") 

    return render_template('index.html', hosts=hosts)

if __name__ == '__main__':
    app.run(debug=True)
    
from fastapi import FastAPI, Header
from fastapi.middleware.cors import CORSMiddleware
from pysondb import db
import cpuinfo
from typing import Union, List
import uuid
import requests
import json
import re
import time

from datetime import datetime, timedelta, date

import traceback
import subprocess
import os
import platform
import threading


import logging
FORMAT = "%(levelname)s:%(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
log = logging.getLogger("app")


import time

from subprocess import Popen, PIPE

from pydantic import BaseModel

class EnvVar(BaseModel):
    name: str
    value: str

class proxyPorts(BaseModel):
    comment: str
    name: str
    port_type: str
    proxy_addr: str
    value: str
    vm_id: str
    #port_type: str

class Action(BaseModel):
    action_id: Union[str, None] = None
    #environment_variables: list[EnvVar] | None = None
    #ports: list[proxyPorts] | None = None
    #environment_variables: List[EnvVar] | None = None
    #ports: List[proxyPorts] | None = None
    environment_variables: List[EnvVar]
    ports: List[proxyPorts]

# Глобальные массивы
# Массив флагов запуска треда на указанные порты
portThreadStatus = {}

# Функция идентификации портов в массиве, для отключения
def port_ident(forward_port_next):
    port_ident = "proxy" + forward_port_next["proxy_addr"] + "type_port" + forward_port_next["type_port"] + "value" + forward_port_next["value"] + "vm_id" + forward_port_next["vm_id"]
    return port_ident

#Создание каталогов под ключи
stdout, stderr = Popen(['mkdir', '-p', '/home/for_agent'], stdout=PIPE, stderr=PIPE).communicate()
stdout, stderr = Popen(['mkdir', '-p', '/home/for_agent/.ssh'], stdout=PIPE, stderr=PIPE).communicate()
stdout, stderr = Popen(['mkdir', '-p', '/home/for_agent/action'], stdout=PIPE, stderr=PIPE).communicate()
a=db.getDb("/home/for_agent/db.json")

AGENT_PORT="7190"
HOST_UUID=""
#BACK="http://192.168.1.55:8000"
#BACK="http://dev.cloudlocalnet.com:8000"
BACK="https://dev.cloudlocalnet.com"

def action_log(type_log, output):
    if type_log == 'out':
        logfile = '/home/for_agent/action_output_log.txt'
    if type_log == 'err':
        logfile = '/home/for_agent/action_error_log.txt'
    f = open(logfile, 'a')
    curdate = str(datetime.now())
    f.write('\n')
    f.write(curdate)
    f.write('\n')
    f.write(output)
    f.write('\n')
    f.close()
    return

# Get UUID from server

def get_uuid():
    try:
        headers = {"Content-Type": "application/json"}
        data={}
        response = requests.post("%s/back/uuid-query"%BACK, headers=headers, json=data)
        log.info("Status Code %s", str(response.status_code))
        log.info("JSON Response %s", str(response.json()))
        return response.json()["host_id"]
    except Exception as inst:
        log.info(inst)
        blank = ""
        return blank


#Make host_id and add to file DB or find already known
while True:
    try:
        q = {"key": "host_id"}
        host_uuid=a.getByQuery(query=q)
        #print(host_uuid)
        if len(host_uuid) == 0:
            #HOST_UUID=str(uuid.uuid4())
            # Тут вставить запрос UUID с бэка
            HOST_UUID=get_uuid()
            a.add({"value":HOST_UUID,"key":"host_id","chapter":"host","name":"","type":"","vm_id":"", "proxy":""})
        else:
            if host_uuid[0]["value"] == "":
                HOST_UUID=get_uuid()
                a.add({"value":HOST_UUID,"key":"host_id","chapter":"host","name":"","type":"","vm_id":"", "proxy":""})
            else:
                HOST_UUID=host_uuid[0]["value"]
    except Exception as inst:
        log.info(inst)
        #HOST_UUID=str(uuid.uuid4())
        HOST_UUID=get_uuid()
        # Тут вставить запрос UUID с бэка
        a.add({"value":HOST_UUID,"key":"host_id","chapter":"host","name":"","type":"","vm_id":"","proxy":""})
    if HOST_UUID != "":
        break
    time.sleep(30)


log.info(HOST_UUID)

#print ("!!!!!!!!!!!!!!!!!!!!!!!!!HOSTNAME")
HOSTNAME=os.uname()[1]

HOST_CORES = cpuinfo.get_cpu_info()["count"]
meminfo = dict((i.split()[0].rstrip(':'),int(i.split()[1])) for i in open('/proc/meminfo').readlines())
mem_kib = meminfo['MemTotal']
HOST_MEM = round(mem_kib/1024/1024,1)


vms = [
    {
        "id": "1",
        "item": "Fake test VM"
    },
    {
        "id": "2",
        "item": "Fake 2 test VM"
    }
]

#Создание ключей
stdout, stderr = Popen(['rm', '/home/for_agent/.ssh/forward.id_rsa'], stdout=PIPE, stderr=PIPE).communicate()
stdout, stderr = Popen(['rm', '/home/for_agent/.ssh/forward.id_rsa.pub'], stdout=PIPE, stderr=PIPE).communicate()
stdout, stderr = Popen(['ssh-keygen', '-f', '/home/for_agent/.ssh/forward.id_rsa', '-N', ''], stdout=PIPE, stderr=PIPE).communicate()
stdout, stderr = Popen(['rm', '/home/for_agent/.ssh/forward_port.id_rsa'], stdout=PIPE, stderr=PIPE).communicate()
stdout, stderr = Popen(['rm', '/home/for_agent/.ssh/forward_port.id_rsa.pub'], stdout=PIPE, stderr=PIPE).communicate()
stdout, stderr = Popen(['ssh-keygen', '-f', '/home/for_agent/.ssh/forward_port.id_rsa', '-N', ''], stdout=PIPE, stderr=PIPE).communicate()
#full_stdout += str(stdout.decode('utf-8'))
#full_stderr += str(stderr.decode('utf-8'))


f = open("/home/for_agent/.ssh/forward.id_rsa.pub", "r")
PUBLIC_KEY_HOST=f.read()
f.close()

f = open("/home/for_agent/.ssh/forward_port.id_rsa.pub", "r")
PUBLIC_KEY_HOST_PORT=f.read()
f.close()

app = FastAPI()

origins = [
    "*"
]


app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        #allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
)

#Все переменные окружения из базы добавляем в среду
log.info(str("Load envs on start"))
try:
    q_envs = {"key": "environment_variable"}
    envs_on_start=a.getByQuery(query=q_envs)
    for env_for_export_on_start in envs_on_start:
        log.info(str(env_for_export_on_start))
        os.environ[env_for_export_on_start["name"]] = env_for_export_on_start["value"]
except Exception as inst:
    log.info(str("Exception in load envs on start"))
    log.info(str(inst))

def register_port(proxy_addr, proxy_external_addr, proxy_external_port, proxy_internal_addr, proxy_internal_port):
#proxy_addr - Внешний адрес прокси-сервер, к которому коннектиться
#proxy_external_addr - Адрес на прокси-сервере, НА который будет вывешиваться порт
#proxy_external_port - Номер порта НА который будет прокситься порт
#proxy_internal_addr - Адрес который будет проксится
#proxy_internal_port - Номер порта который будет проксится
#ssh -N -R 20000:localhost:80 -o ServerAliveInterval=10 -o ExitOnForwardFailure=yes forward@192.168.1.116 -p 22 -i ~/.ssh/id_rsa
#ssh -N -R 20000:localhost:80 -o ServerAliveInterval=10 -o ExitOnForwardFailure=yes forward@192.168.1.116 -p 22 -i ~/.ssh/id_rsa
    log.info("-------------regestry port       %s %s %s %s "%(proxy_addr, proxy_external_addr, proxy_external_port, proxy_internal_port))
    try:
        while True:
            #stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/mnt/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate(timeout=source_timeout)
            stdout, stderr = Popen(['ssh', '-N', '-R', proxy_external_addr+':'+proxy_external_port+':' + proxy_internal_addr + ':'+proxy_internal_port, 
                '-o', 'ServerAliveInterval=10', '-o', 'ExitOnForwardFailure=yes', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', 
                'forward@'+proxy_addr, '-p', '22', '-i', '/home/for_agent/.ssh/forward.id_rsa'], stdout=PIPE, stderr=PIPE).communicate()
            log.info(str(stdout.decode('utf-8')))
            log.info(str(stderr.decode('utf-8')))
            time.sleep(5)
    except Exception as inst:
        allowedExecution=True
        log.info(inst)
    return

def register_port_ports(proxy_addr, proxy_external_addr, proxy_external_port, proxy_internal_addr, proxy_internal_port,port_ident):
#proxy_addr - Внешний адрес прокси-сервер, к которому коннектиться
#proxy_external_addr - Адрес на прокси-сервере, НА который будет вывешиваться порт
#proxy_external_port - Номер порта НА который будет прокситься порт
#proxy_internal_addr - Адрес который будет проксится
#proxy_internal_port - Номер порта который будет проксится
#ssh -N -R 20000:localhost:80 -o ServerAliveInterval=10 -o ExitOnForwardFailure=yes forward@192.168.1.116 -p 22 -i ~/.ssh/id_rsa
#ssh -N -R 20000:localhost:80 -o ServerAliveInterval=10 -o ExitOnForwardFailure=yes forward@192.168.1.116 -p 22 -i ~/.ssh/id_rsa
    log.info("-------------regestry ports port   %s %s %s %s "%(proxy_addr, proxy_external_addr, proxy_external_port, proxy_internal_port))
    try:
        while True:
            #stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/mnt/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate(timeout=source_timeout)
            stdout, stderr = Popen(['ssh', '-N', '-R', proxy_external_addr+':'+proxy_external_port+':' + proxy_internal_addr + ':'+proxy_internal_port, 
                '-o', 'ServerAliveInterval=10', '-o', 'ExitOnForwardFailure=yes', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', 
                'forward@'+proxy_addr, '-p', '22', '-i', '/home/for_agent/.ssh/forward_port.id_rsa'], stdout=PIPE, stderr=PIPE).communicate()
            log.info(str(stdout.decode('utf-8')))
            log.info(str(stderr.decode('utf-8')))
            time.sleep(5)
            if portThreadStatus[port_ident]!="Running":
                return
    except Exception as inst:
        allowedExecution=True
        log.info(inst)
    return

# Зарегистрировать порт самого агента на прокси(делается каждый раз, когда агент рестартует и на новый ключ и на новый порт)
# Запрашиваем адрес и порт для проксирования порта 7190. То есть порт 7190 хоста агента будет проксироваться на указанный прокси сервер на указанные адрес и порт
while True:
    AUTHORIZED_USER=""
    try:
        q = {"key": "authorized_user"}
        auth_users=a.getByQuery(query=q)
        if len(auth_users) == 0:
            #a.add({"value":str(user_id),"key":"authorized_user","chapter":"host","name":"","type":"","vm_id":"","proxy":""})
            AUTHORIZED_USER=""
        else:
            AUTHORIZED_USER=auth_users[0]["value"]
    except Exception as inst:
        AUTHORIZED_USER=""
        log.info(inst)
    
    port_on_sent = []
    try:
        q = {"key": "port"}
        port_db=a.getByQuery(query=q)
    except Exception as inst:
        port_db=[]
        log.info(inst)

    for port_one in port_db:
        tmp_port = {"name":port_one["name"],"type_port":port_one["type"],"value":port_one["value"],"vm_id":port_one["vm_id"],"proxy":port_one["proxy"]}
        port_on_sent.append(tmp_port)

    try:
        register_headers = {"Content-Type": "application/json"}
        register_data={"host_id":HOST_UUID, "authorized_user":AUTHORIZED_USER, "host_key":PUBLIC_KEY_HOST, "host_name": HOSTNAME, "port_key": PUBLIC_KEY_HOST_PORT, "ports":port_on_sent}
        log.info(register_data)
        response = requests.post("%s/back/register-agent"%BACK, headers=register_headers, json=register_data)
        log.info(response)
        log.info("Status Code %s", str(response.status_code))
        log.info("JSON Response %s", str(response.json()))

        #if 'action_timeout' in action.keys():
        if 'proxy_addr' in response.json().keys() and 'proxy_ext_addr' in response.json().keys() and 'proxy_ext_port' in response.json().keys():
            break

    except Exception as inst:
        #response={}
        log.info(inst)
    
    time.sleep(60)

#Запуск регистрации порта агента
log.info("Agent port register proxy_addr:%s proxy_ext_addr:%s proxy_ext_port:%s AGENT_PORT:%s"%(str(response.json()["proxy_addr"]), 
    str(response.json()["proxy_ext_addr"]), str(response.json()["proxy_ext_port"]), AGENT_PORT))

# Тред тоннеля на прокси для агента
register_thread = threading.Thread(target=register_port, name="Proxyng port", args=(response.json()["proxy_addr"],
    response.json()["proxy_ext_addr"],response.json()["proxy_ext_port"],"0.0.0.0",AGENT_PORT), daemon=True)
register_thread.start()

# Запуск региcтрации портов на разрешенных прокси
def run_ports_forward(ports):
    #for forward_port_next in response.json()["ports"]:
    for forward_port_next in ports:
        log.info("-------------regestry ports:   %s "%(forward_port_next))
        if forward_port_next["vm_id"] == "":
            addr_on_agent_side = "0.0.0.0"
        else:
            # Тут будет запрос IP адреса той виртуалки, порт которой надо прокинуть на прокси сервер
            addr_on_agent_side = "0.0.0.0"
        # Идентификатор треда который будет держать подключение с портом на прокси
        #port_ident = "proxy" + forward_port_next["proxy_addr"] + "type_port" + forward_port_next["type_port"] + "value" + forward_port_next["value"] + "vm_id" + forward_port_next["vm_id"]
        port_ident_value = port_ident(forward_port_next)
        log.info("-------------regestry ports: port ident: %s  %s "%(port_ident_value,forward_port_next))

        # Если есть все данные для запуска, то пускаем, если нет - то тред тоннеля не запускается
        if forward_port_next["proxy_addr"] != "" and forward_port_next["proxy_ext_addr"] != "" and forward_port_next["proxy_ext_port"] != "":
            # Ставим статус для того чтобы процесс мог отключится
            portThreadStatus[port_ident_value]="Running"
            register_thread = threading.Thread(target=register_port_ports, name="Proxyng port"+forward_port_next["name"], 
                args=(forward_port_next["proxy_addr"], forward_port_next["proxy_ext_addr"], forward_port_next["proxy_ext_port"],
                    addr_on_agent_side,forward_port_next["value"],port_ident_value ), daemon=True)
            register_thread.start()


run_ports_forward(response.json()["ports"])

#register_port(response.json()["proxy_addr"],response.json()["proxy_ext_addr"],response.json()["proxy_ext_port"],AGENT_PORT)

#Добавление переменных окружения в базу и в окружение
async def add_environment_variables(envs):
    log.info("Run add_environment_variables")
    #print(envs)
    for env_for_export in envs:
        log.info("Export %s %s"%(env_for_export.name, env_for_export.value) )
        #HOST_UUID=host_uuid[0]["value"]
        #record_id=a.getByQuery(query=q)[0]["id"]
        #is_deleted = a.deleteById(pk=record_id)

        try:
            q = {"key": "environment_variable", "name":env_for_export.name}
            env_value=a.getByQuery(query=q)
            #print("Success query")
            if len(env_value) == 0:
                #HOST_UUID=str(uuid.uuid4())
                # Тут вставить запрос UUID с бэка
                a.add({"name":env_for_export.name,"value":env_for_export.value,"key":"environment_variable","chapter":"environment","type":"","vm_id":"","proxy":""})
                os.environ[env_for_export.name] = env_for_export.value
            else:
                record_id=env_value[0]["id"]
                is_deleted = a.deleteById(pk=record_id)
                a.add({"name":env_for_export.name,"value":env_for_export.value,"key":"environment_variable","chapter":"environment","type":"","vm_id":"","proxy":""})
                os.environ[env_for_export.name] = env_for_export.value
        except Exception as inst:
            log.info("Exception")
            log.info(inst)
            os.environ[env_for_export.name] = env_for_export.value


async def add_proxy_ports(proxy_ports, authorization):
    log.info("Run add_proxy_ports")
    # Add ports 
    if (proxy_ports):
        #if response_action.json()["ports"] != None:
        if proxy_ports != None:
            #for port_add in response_action.json()["ports"]:
            for port_add in proxy_ports:
                log.info(port_add)
                # Проверка наличия порта в локальной базе и добавление если его нет, а если есть обновление данных(удаление и добавление по новой):
                try:
                    q = {"key": "port", "value": port_add.value, "vm_id": port_add.vm_id, "type": port_add.port_type}
                    port_db=a.getByQuery(query=q)
                    if len(port_db) == 0:
                        #Добавляем порт в локальную базу так как его нет
                        a.add({"value":str(port_add.value),"key":"port","chapter":"host","name":str(port_add.name),
                            "type":str(port_add.port_type),"vm_id":str(port_add.vm_id), "proxy":str(port_add.proxy_addr)})
                    else:
                        #Если порт есть, удаляем его и его данные и добавляем по новой, для обновления записи. Почему не апдейт? Да хрен знает.
                        record_id=a.getByQuery(query=q)[0]["id"]
                        is_deleted = a.deleteById(pk=record_id)
                        log.info(is_deleted)
                        a.add({"value":str(port_add.value),"key":"port","chapter":"host","name":str(port_add.name),
                            "type":str(port_add.port_type),"vm_id":str(port_add.vm_id), "proxy":str(port_add.proxy_addr)})
                except Exception as inst:
                    log.info(inst)    
            # Добавление всех портов в данные по хосту и отправка нового набора
            # Запрос всех портов в локальной БД
            q = {"key": "port"}
            port_db=a.getByQuery(query=q)
            port_on_sent=[]

            log.info(port_db)
            for port_one in port_db:
                tmp_port = {"name":port_one["name"],"type_port":port_one["type"],"value":port_one["value"],"vm_id":port_one["vm_id"], "proxy":port_one["proxy"] }
                port_on_sent.append(tmp_port)

            q = {"key": "authorized_user"}
            auth_users=a.getByQuery(query=q)
            if len(auth_users) == 0:
                auth_user_on_sent = ""
            else:
                auth_user_on_sent = auth_users[0]["value"]
            log.info(auth_users)
            headers = {"Content-Type": "application/json", "Authorization": authorization}
            data ={"host_id":HOST_UUID, "authorized_user":auth_user_on_sent,"ports":port_on_sent}
            response = requests.post("%s/back/ports-update"%BACK, headers=headers, json=data)
            log.info("Status Code %s"%str(response.status_code))
            log.info("JSON Response %s"%str(response.json()))


async def action_execute(action):
    log.info("execute action %s"%action)

    full_stdout = ""
    full_stderr = ""

    #if (action["action_timeout"]):
    if 'action_timeout' in action.keys():
        action_timeout=int(action["action_timeout"])
    else:
        action_timeout=int(255)

    #if (action["source_timeout"]):
    if 'source_timeout' in action.keys():
        source_timeout=int(action["source_timeout"])
    else:
        source_timeout=int(255)

    log.info(" %s %s "%(source_timeout, action_timeout))

    #Clone action repository(Auth type: None, http_pass, ssh_key)
    log.info("Clear directory for action")
    #stdout, stderr = Popen(['rm', '-r', '/mnt/action/'+ str(action["id"])], stdout=PIPE, text=True).communicate()
    stdout, stderr = Popen(['rm', '-r', '/home/for_agent/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate()
    #full_stdout += str(stdout.decode('utf-8').splitlines())
    full_stdout += str(stdout.decode('utf-8'))
    full_stderr += str(stderr.decode('utf-8'))

    if action["auth_type"] == "log_pass":
        log.info("auth_type log_pass")
        log.info("clone action from source %s"%action["source"])

        split_addr = action["source"].split('://')
        log.info("split addr %s"%(str(split_addr)))

        #stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/mnt/action/'+ str(action["id"])], stdout=PIPE, text=True).communicate()
        stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(split_addr[0]) + '://' + str(action["source_credentials"]) + '@' + str(split_addr[1]),'/home/for_agent/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate(timeout=source_timeout)
        full_stdout += str(stdout.decode('utf-8'))
        full_stderr += str(stderr.decode('utf-8'))

        log.info("Set branch action from source %s"%action["branch"])
        #stdout_gitcheckout, stderr_gitcheckout = Popen(['cd','/mnt/action/'+ str(action["id"]),'&&', 'git checkout ' + str(action["branch"])], stdout=PIPE).communicate()
        stdout, stderr = Popen(['git','checkout' , str(action["branch"])], stdout=PIPE, cwd='/home/for_agent/action/'+ str(action["id"]), stderr=PIPE).communicate()
        full_stdout += str(stdout.decode('utf-8'))
        full_stderr += str(stderr.decode('utf-8'))


    if action["auth_type"] == "token":

        split_addr = action["source"].split('://')
        log.info("split addr %s"%(str(split_addr)))

        log.info("auth_type token")
        log.info("clone action from source %s"%action["source"])


        #stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/mnt/action/'+ str(action["id"])], stdout=PIPE, text=True).communicate()
        stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(split_addr[0]) + '://' + str(action["source_credentials"]) + '@' + str(split_addr[1]),'/home/for_agent/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate(timeout=source_timeout)
        full_stdout += str(stdout.decode('utf-8'))
        full_stderr += str(stderr.decode('utf-8'))

        log.info("Set branch action from source %s"%action["branch"])
        #stdout_gitcheckout, stderr_gitcheckout = Popen(['cd','/mnt/action/'+ str(action["id"]),'&&', 'git checkout ' + str(action["branch"])], stdout=PIPE).communicate()
        stdout, stderr = Popen(['git','checkout' , str(action["branch"])], stdout=PIPE, cwd='/home/for_agent/action/'+ str(action["id"]), stderr=PIPE).communicate()
        full_stdout += str(stdout.decode('utf-8'))
        full_stderr += str(stderr.decode('utf-8'))


    if action["auth_type"] == "private_key":

        privkey_file = '/home/for_agent/action/privkey.txt'
        f = open(privkey_file, 'w')
        f.write(str(action["source_credentials"]))
        f.write('\n')
        f.close()


        log.info("auth_type private_key")
        log.info("clone action from source %s"%action["source"])
        try:
            stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/home/for_agent/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE, env=dict(os.environ, GIT_SSH_COMMAND="ssh -i /home/for_agent/action/privkey.txt")).communicate(timeout=source_timeout)
            #stdout, stderr = Popen([git_env_key, 'git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/home/for_agent/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate(timeout=source_timeout)
        except Exception as inst:
            stderr = inst
            log.info(inst)

        log.info("out: %s %s"%(str(stdout), str(stderr)))

        full_stdout += str(stdout.decode('utf-8'))
        full_stderr += str(stderr.decode('utf-8'))

        log.info("Set branch action from source %s"%action["branch"])
        #stdout_gitcheckout, stderr_gitcheckout = Popen(['cd','/mnt/action/'+ str(action["id"]),'&&', 'git checkout ' + str(action["branch"])], stdout=PIPE).communicate()
        stdout, stderr = Popen(['git','checkout' , str(action["branch"])], stdout=PIPE, cwd='/home/for_agent/action/'+ str(action["id"]), stderr=PIPE).communicate()
        full_stdout += str(stdout.decode('utf-8'))
        full_stderr += str(stderr.decode('utf-8'))



    else:
        log.info("auth_type another")
        log.info("clone action from source %s"%action["source"])
        #stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/mnt/action/'+ str(action["id"])], stdout=PIPE, text=True).communicate()
        stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/home/for_agent/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate(timeout=source_timeout)
        full_stdout += str(stdout.decode('utf-8'))
        full_stderr += str(stderr.decode('utf-8'))

        log.info("Set branch action from source %s"%action["branch"])
        #stdout_gitcheckout, stderr_gitcheckout = Popen(['cd','/mnt/action/'+ str(action["id"]),'&&', 'git checkout ' + str(action["branch"])], stdout=PIPE).communicate()
        stdout, stderr = Popen(['git','checkout' , str(action["branch"])], stdout=PIPE, cwd='/home/for_agent/action/'+ str(action["id"]), stderr=PIPE).communicate()
        full_stdout += str(stdout.decode('utf-8'))
        full_stderr += str(stderr.decode('utf-8'))




    log.info("execute action %s"%action)
    stdout, stderr = Popen(['/home/for_agent/action/' + str(action["id"]) + "/"+ str(action["source_path"]) + str(action["source_run_file"])], 
        cwd='/home/for_agent/action/' + str(action["id"]) + "/"+ str(action["source_path"]) ,stdout=PIPE, stderr=PIPE).communicate(timeout=action_timeout)
    #print(str(stdout.decode('utf-8')))
    #print(str(stderr.decode('utf-8')))

    full_stdout += str(stdout.decode('utf-8'))
    full_stderr += str(stderr.decode('utf-8'))

    log.info(" %s %s"%(full_stdout, full_stderr))

    #print(stdout_clear, stderr_clear, stdout_gitclone, stderr_gitclone, stdout_gitcheckout, stderr_gitcheckout, stdout_runaction, stderr_runaction)
    #full_output = stdout_clear + stderr_clear + stdout_gitclone + stderr_gitclone + stdout_gitcheckout + stderr_gitcheckout + stdout_runaction + stderr_runaction
    #full_output = full_output
    #full_output = json.dumps(str(stdout_clear) + str(stderr_clear) + str(stdout_gitclone) + str(stderr_gitclone) + str(stdout_gitcheckout) + str(stderr_gitcheckout) + str(stdout_runaction) + str(stderr_runaction)).replace('"', "'")

    #full_output = json.dumps((full_stdout + full_stderr).replace('"', "'"))
    #full_output = (full_stdout + full_stderr).replace('"', "'")
    #full_output = (full_stdout + full_stderr).replace('"', "'")
    full_stdout = full_stdout.replace('"', "'")
    full_stderr = full_stderr.replace('"', "'")
    return full_stdout, full_stderr

@app.get("/", tags=["root"])
async def read_root() -> dict:
    return {"message": "Welcome to VM list"}

@app.get("/agent/ping", tags=["ping"])
async def ping_root(authorization: Union[str, None] = Header(default=None)):
    #print("Authorization: %s"%authorization)
    #headers = {"Authorization": authorization}
    #data ={}
    #response = requests.get("%s/users/me"%BACK, headers=headers, json=data)
    #print("Status Code", response.status_code)
    #print("JSON Response ", response.json())
    try:
        q = {"key": "host_id"}
        host_id=a.getByQuery(query=q)[0]["value"]
    except:
        host_id="error"
    try:
        q = {"key": "authorized_user"}
        authorized_user=a.getByQuery(query=q)[0]["value"]
    except:
        authorized_user=None

    #return {"Bearer": authorization}
    return {"host_id": host_id, "cores":HOST_CORES, "mem":HOST_MEM, "authorized_user":authorized_user}

@app.get("/agent/bind", tags=["bind"])
async def bind_host(authorization: Union[str, None] = Header(default=None)):
    log.info("Authorization: %s"%authorization)
    #headers = {"Authorization": authorization}
    #data ={}
    #response = requests.get("%s/users/me"%BACK, headers=headers, json=data)
    #print("Status Code", response.status_code)
    #print("JSON Response ", response.json())

    headers = {"Content-Type": "application/json", "Authorization": authorization}
    data ={"host_id":HOST_UUID}
    response = requests.post("%s/back/host-bind"%BACK, headers=headers, json=data)
    log.info("Status Code %s"%str(response.status_code))
    log.info("JSON Response %s"%str(response.json()))

    try:
        user_id = response.json()["id"]
        log.info(user_id)
        try:
            q = {"key": "authorized_user"}
            auth_users=a.getByQuery(query=q)
            if len(auth_users) == 0:
                a.add({"value":str(user_id),"key":"authorized_user","chapter":"host","name":"","type":"","vm_id":"","proxy":""})
                #return {"Detail": "Success binded"}
                run_ports_forward(response.json()["ports"])
                return {"message": "OK"}
            else:
                record_id=a.getByQuery(query=q)[0]["id"]
                is_deleted = a.deleteById(pk=record_id)
                log.info(is_deleted)
                a.add({"value":str(user_id),"key":"authorized_user","chapter":"host","name":"","type":"","vm_id":"","proxy":""})
                return {"message":"OK","Detail":"Already binded(rebind for current) / " + str(response.json()["message"])}
        except Exception as inst:
            log.info(inst)
    except:
        log.info("Detail:Unauthorized")
        return {"message":"Unauthorized"}
    return {"message":"Unauthorized"}

@app.get("/agent/unbind", tags=["bind"])
async def unbind_host(authorization: Union[str, None] = Header(default=None)):
    log.info("Authorization: %s"%authorization)
    #headers = {"Authorization": authorization}
    #data ={}
    #response = requests.get("%s/users/me"%BACK, headers=headers, json=data)
    #print("Status Code", response.status_code)
    #print("JSON Response ", response.json())

    headers = {"Content-Type": "application/json", "Authorization": authorization}
    data ={"host_id":HOST_UUID}
    response = requests.post("%s/back/host-unbind"%BACK, headers=headers, json=data)
    log.info("Status Code %s"%str(response.status_code))
    log.info("JSON Response %s"%str(response.json()))
    try:
        if response.json()["message"] == "OK":
            # Stop all ports forward
            for stop_port in portThreadStatus.keys():
                portThreadStatus[stop_port] = "Stop"
                log.info("Stop port index:%s"%(stop_port))

            try:
                q = {"key": "authorized_user"}
                auth_users=a.getByQuery(query=q)
                if len(auth_users) == 0:
                    return {"message": "OK", "Detail":"In host BD missing"}
                else:
                    record_id=a.getByQuery(query=q)[0]["id"]
                    is_deleted = a.deleteById(pk=record_id)
                    log.info(is_deleted)
                    return {"message":"OK"}
            except Exception as inst:
                log.info(inst)    
        else:
            return {"message":str(response.json()["message"])}
            
        # 
        # user_id = response.json()["id"]
        # print(user_id)
        # try:
        #     q = {"key": "authorized_user"}
        #     auth_users=a.getByQuery(query=q)
        #     if len(auth_users) == 0:
        #         #a.add({"value":str(user_id),"key":"authorized_user"},"chapter":"host","name":"","type":"","vm_id":"","proxy":"")
        #         return {"message": "Already Unbinded"}
        #     else:
        #         if auth_users[0]["value"] == user_id :
        #             print(auth_users)
        #             record_id=a.getByQuery(query=q)[0]["id"]
        #             is_deleted = a.deleteById(pk=record_id)
        #             print(is_deleted)
        #             return {"message":"OK"}
        #         else:
        #             print("User does not match")
        #             return {"message":"User does not match"}
        # except Exception as inst:
        #     print(inst)

    except:
        log.info("Detail:Unauthorized")
        return {"message":"Unauthorized"}
    return {"message":"Unauthorized"}


@app.post("/agent/action", tags=["action"])
#async def start_action(authorization: Union[str, None] = Header(default=None), action: Action):
async def start_action(action: Action, authorization: Union[str, None] = Header(default=None)):
    log.info("Authorization: %s"%authorization)
    #headers = {"Content-Type": "application/json", "Authorization": authorization}
    #data ={}
    #response = requests.get("%s/users/me"%BACK, headers=headers, json=data)
    #print("Status Code", response.status_code)
    #print("JSON Response ", response.json())

    # try:
    #     user_id = response.json()["id"]
    #     print(user_id)
    # except Exception as inst:
    #     print("Except %s (Unuthorized)"%inst)
    #     user_id=""
    # try:
    #     q = {"key": "authorized_user"}
    #     auth_users=a.getByQuery(query=q)
    #     if len(auth_users) == 0:
    #         allowedExecution=True
    #     else:
    #         if auth_users[0]["value"] == user_id :
    #             allowedExecution=True
    #         else:
    #             allowedExecution=False
    # except Exception as inst:
    #     allowedExecution=True
    #     print(inst)
    #user_id = response.json()["id"]

    # Проверка прав, что юзер может исполнять экшн на этом хосту
    headers = {"Content-Type": "application/json", "Authorization": authorization}
    data ={"host_id":HOST_UUID}
    response = requests.post("%s/back/check-permissions"%BACK, headers=headers, json=data)
    log.info("Status Code %s"%str(response.status_code))
    log.info("JSON Response %s"%str(response.json()))

    allowedExecution = response.json()["allowedExecution"]

    #Variables for export to Enviroment
    #for env_for_export in action.environment_variables:
    #    print("%s %s"%(env_for_export.name, env_for_export.value) )


    if allowedExecution=="True":
        # Добавляем переменные окружения до старта экшена
        if (action.environment_variables):
            log.info(action.environment_variables)
            await add_environment_variables(action.environment_variables)
        # Добавляем порты для форвардинга
        if (action.ports):
            log.info(action.ports)
            await add_proxy_ports(action.ports, authorization)

        log.info(action.action_id)
        data={"action_id": action.action_id}
        #print("DATA: %s"%data)
        response_action = requests.post("%s/action"%BACK, headers=headers, json=data)
        log.info("Status Code %s"%str(response_action.status_code))
        log.info("JSON Response %s"%str(response_action.json()))
        log.info(response_action.json().keys())
        action_log('out', str(response_action.json()))

        """
        # Add ports 
        if "ports" in response_action.json().keys():
            if response_action.json()["ports"] != None:
                for port_add in response_action.json()["ports"]:
                    log.info(port_add)
                    # Проверка наличия порта в локальной базе и добавление если его нет, а если есть обновление данных(удаление и добавление по новой):
                    try:
                        q = {"key": "port", "value": port_add["value"], "vm_id": port_add["vm_id"]}
                        port_db=a.getByQuery(query=q)
                        if len(port_db) == 0:
                            #Добавляем порт в локальную базу так как его нет
                            a.add({"value":str(port_add["value"]),"key":"port","chapter":"host","name":str(port_add["name"]),
                                "type":str(port_add["port_type"]),"vm_id":str(port_add["vm_id"])})
                        else:
                            #Если порт есть, удаляем его и его данные и добавляем по новой, для обновления записи. Почему не апдейт? Да хрен знает.
                            record_id=a.getByQuery(query=q)[0]["id"]
                            is_deleted = a.deleteById(pk=record_id)
                            log.info(is_deleted)
                            a.add({"value":str(port_add["value"]),"key":"port","chapter":"host","name":str(port_add["name"]),
                                "type":str(port_add["port_type"]),"vm_id":str(port_add["vm_id"])})
                    except Exception as inst:
                        log.info(inst)    
                # Добавление всех портов в данные по хосту и отправка нового набора
                # Запрос всех портов в локальной БД
                q = {"key": "port"}
                port_db=a.getByQuery(query=q)
                port_on_sent=[]

                log.info(port_db)
                for port_one in port_db:
                    tmp_port = {"name":port_one["name"],"type_port":port_one["type"],"value":port_one["value"],"vm_id":port_one["vm_id"] }
                    port_on_sent.append(tmp_port)

                q = {"key": "authorized_user"}
                auth_users=a.getByQuery(query=q)
                if len(auth_users) == 0:
                    auth_user_on_sent = ""
                else:
                    auth_user_on_sent = auth_users[0]["value"]
                log.info(auth_users)
                headers = {"Content-Type": "application/json", "Authorization": authorization}
                data ={"host_id":HOST_UUID, "authorized_user":auth_user_on_sent,"ports":port_on_sent}
                response = requests.post("%s/back/ports-update"%BACK, headers=headers, json=data)
                log.info("Status Code %s"%str(response.status_code))
                log.info("JSON Response %s"%str(response.json()))
        """
        log.info("Start Action")
        try:
            full_stdout, full_stderr = await action_execute(response_action.json())
        except:
            full_stdout = "ERROR execute action"
            full_stderr = "ERROR execute action"
        action_log('out', full_stdout)
        action_log('err', full_stderr)
        return {"Detail":"Execute action", "full_stdout": full_stdout, "full_stderr": full_stderr}
    else:
        return {"Detail":"Execute action denied"}
        



@app.get("/agent/get_actions_logs", tags=["get_actions_logs"])
async def get_actions_logs(authorization: Union[str, None] = Header(default=None)):
    log.info("Authorization: %s"%authorization)

    # Проверка прав, что юзер может исполнять экшн на этом хосту
    headers = {"Content-Type": "application/json", "Authorization": authorization}
    data ={"host_id":HOST_UUID}
    response = requests.post("%s/back/check-permissions"%BACK, headers=headers, json=data)
    log.info("Status Code %s"%str(response.status_code))
    log.info("JSON Response %s"%str(response.json()))

    allowedExecution = response.json()["allowedExecution"]

    if allowedExecution=="True":

        try:
            full_stdout = open('/home/for_agent/action_output_log.txt', 'r').read()
            full_stderr = open('/home/for_agent/action_error_log.txt', 'r').read()
        except:
            full_stdout = "no file"
            full_stderr = "no file"

        return {"Detail":"Get logs actions", "full_stdout": full_stdout, "full_stderr": full_stderr}
    else:
        return {"Detail":"Get actions logs denied"}
        


@app.get("/agent/cpuinfo", tags=["cpuinfo"])
async def cpu_info():
    return {"cpuinfo": cpuinfo.get_cpu_info()}


@app.get("/vm", tags=["vms"])
async def get_vms() -> dict:
    print("Get vms:%s"%vms)
    return { "data": vms }


@app.post("/vm", tags=["vms"])
async def add_vm(vm: dict) -> dict:
    vms.append(vm)
    print("Add vm:%s"%vms)
    return {
        "data": { "VM added." }
    }


@app.put("/vm/{id}", tags=["vms"])
async def update_vm(id: int, body: dict) -> dict:
    for vm in vms:
        if int(vm["id"]) == id:
            vm["item"] = body["item"]
            print("Update VMs:%s"%vms)
            return {
                "data": f"VM with id {id} has been updated."
            }

    print("Update VMs:%s"%vms)
    return {
        "data": f"VM with id {id} not found."
    }


@app.delete("/vm/{id}", tags=["vms"])
async def delete_vm(id: int) -> dict:
    for vm in vms:
        if int(vm["id"]) == id:
            vms.remove(todo)
            print("Remove VMs:%s"%vms)
            return {
                "data": f"VM with id {id} has been removed."
            }

    print("Update VMs:%s"%vms)
    return {
        "data": f"VM with id {id} not found."
    }

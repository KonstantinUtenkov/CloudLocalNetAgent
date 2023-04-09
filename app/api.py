from fastapi import FastAPI, Header
from fastapi.middleware.cors import CORSMiddleware
from pysondb import db
import cpuinfo
from typing import Union
import uuid
import requests
import json
import re
import time

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

class Action(BaseModel):
    action_id: Union[str, None] = None
    environment_variables: list[EnvVar] | None = None

#Создание каталогов под ключи
stdout, stderr = Popen(['mkdir', '-p', '/home/for_agent'], stdout=PIPE, stderr=PIPE).communicate()
stdout, stderr = Popen(['mkdir', '-p', '/home/for_agent/.ssh'], stdout=PIPE, stderr=PIPE).communicate()
a=db.getDb("/home/for_agent/db.json")

AGENT_PORT="7190"
HOST_UUID=""
#BACK="http://192.168.1.55:8000"
#BACK="http://dev.cloudlocalnet.com:8000"
BACK="https://dev.cloudlocalnet.com"


# Get UUID from server

def get_uuid():
    headers = {"Content-Type": "application/json"}
    data={}
    response = requests.post("%s/back/uuid-query"%BACK, headers=headers, json=data)
    print("Status Code", response.status_code)
    print("JSON Response ", response.json())
    return response.json()["host_id"]



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
            a.add({"value":HOST_UUID,"key":"host_id","chapter":"host","name":"","type":"","vm_id":""})
        else:
            HOST_UUID=host_uuid[0]["value"]
    except Exception as inst:
        print(inst)
        #HOST_UUID=str(uuid.uuid4())
        HOST_UUID=get_uuid()
        # Тут вставить запрос UUID с бэка
        a.add({"value":HOST_UUID,"key":"host_id","chapter":"host","name":"","type":"","vm_id":""})
    if HOST_UUID != "":
        break
    time.sleep(30)


print (HOST_UUID)

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
    print("regestry port")
    log.info("%s %s %s %s "%(proxy_addr, proxy_external_addr, proxy_external_port, proxy_internal_port))
    try:
        while True:
            #stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/mnt/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate(timeout=source_timeout)
            stdout, stderr = Popen(['ssh', '-N', '-R', proxy_external_addr+':'+proxy_external_port+':' + proxy_internal_addr + ':'+proxy_internal_port,  '-o', 'ServerAliveInterval=10', '-o', 'ExitOnForwardFailure=yes', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', 'forward@'+proxy_addr, '-p', '22', '-i', '/home/for_agent/.ssh/forward.id_rsa'], stdout=PIPE, stderr=PIPE).communicate()
            log.info(str(stdout.decode('utf-8')))
            log.info(str(stderr.decode('utf-8')))
            time.sleep(60)
    except Exception as inst:
        allowedExecution=True
        print(inst)
    return

# Зарегистрировать порт самого агента на прокси(делается каждый раз, когда агент рестартует и на новый ключ и на новый порт)
# Запрашиваем адрес и порт для проксирования порта 7190. То есть порт 7190 хоста агента будет проксироваться на указанный прокси сервер на указанные адрес и порт
while True:
    AUTHORIZED_USER=""
    try:
        q = {"key": "authorized_user"}
        auth_users=a.getByQuery(query=q)
        if len(auth_users) == 0:
            #a.add({"value":str(user_id),"key":"authorized_user","chapter":"host","name":"","type":"","vm_id":""})
            AUTHORIZED_USER=""
        else:
            AUTHORIZED_USER=auth_users[0]["value"]
    except Exception as inst:
        AUTHORIZED_USER=""
        print(inst)
    
    port_on_sent = []
    try:
        q = {"key": "port"}
        port_db=a.getByQuery(query=q)
    except Exception as inst:
        port_db=[]
        print(inst)

    for port_one in port_db:
        tmp_port = {"name":port_one["name"],"type_port":port_one["type"],"value":port_one["value"],"vm_id":port_one["vm_id"] }
        port_on_sent.append(tmp_port)

    
    register_headers = {"Content-Type": "application/json"}
    register_data={"host_id":HOST_UUID, "authorized_user":AUTHORIZED_USER, "host_key":PUBLIC_KEY_HOST, "host_name": HOSTNAME, "port_key": PUBLIC_KEY_HOST_PORT, "ports":port_on_sent}
    response = requests.post("%s/back/register-agent"%BACK, headers=register_headers, json=register_data)
    print(response)
    print("Status Code", response.status_code)
    print("JSON Response ", response.json())


    #if 'action_timeout' in action.keys():
    if 'proxy_addr' in response.json().keys() and 'proxy_ext_addr' in response.json().keys() and 'proxy_ext_port' in response.json():
        break
    
    time.sleep(60)


#Запуск регистрации порта
log.info(str(response.json()["proxy_addr"]))
log.info(str(response.json()["proxy_ext_addr"]))
log.info(str(response.json()["proxy_ext_port"]))
log.info(str(AGENT_PORT))

register_thread = threading.Thread(target=register_port, name="Proxyng port", args=(response.json()["proxy_addr"],response.json()["proxy_ext_addr"],response.json()["proxy_ext_port"],"0.0.0.0",AGENT_PORT), daemon=True)
register_thread.start()
#register_port(response.json()["proxy_addr"],response.json()["proxy_ext_addr"],response.json()["proxy_ext_port"],AGENT_PORT)



#Добавление переменных окружения в базу и в окружение
async def add_environment_variables(envs):
    print("Run add_environment_variables")
    #print(envs)
    for env_for_export in envs:
        print("Export %s %s"%(env_for_export.name, env_for_export.value) )
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
                a.add({"name":env_for_export.name,"value":env_for_export.value,"key":"environment_variable","chapter":"environment","type":"","vm_id":""})
                os.environ[env_for_export.name] = env_for_export.value
            else:
                record_id=env_value[0]["id"]
                is_deleted = a.deleteById(pk=record_id)
                a.add({"name":env_for_export.name,"value":env_for_export.value,"key":"environment_variable","chapter":"environment","type":"","vm_id":""})
                os.environ[env_for_export.name] = env_for_export.value
        except Exception as inst:
            print("Exception")
            print(inst)
            os.environ[env_for_export.name] = env_for_export.value



# Запуск проксирования сохраненных портов(то есть надо запросить список сохраненных портов и их запроксировать)



async def action_execute(action):
    print("execute action %s"%action)

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

    print(source_timeout, action_timeout)

    #Clone action repository(Auth type: None, http_pass, ssh_key)
    print("Clear directory for action")
    #stdout, stderr = Popen(['rm', '-r', '/mnt/action/'+ str(action["id"])], stdout=PIPE, text=True).communicate()
    stdout, stderr = Popen(['rm', '-r', '/home/for_agent/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate()
    #full_stdout += str(stdout.decode('utf-8').splitlines())
    full_stdout += str(stdout.decode('utf-8'))
    full_stderr += str(stderr.decode('utf-8'))

    print("clone action from source %s"%action["source"])
    #stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/mnt/action/'+ str(action["id"])], stdout=PIPE, text=True).communicate()
    stdout, stderr = Popen(['git', '-c', 'http.sslVerify=false', 'clone', str(action["source"]), '/home/for_agent/action/'+ str(action["id"])], stdout=PIPE, stderr=PIPE).communicate(timeout=source_timeout)
    full_stdout += str(stdout.decode('utf-8'))
    full_stderr += str(stderr.decode('utf-8'))

    print("Set branch action from source %s"%action["branch"])
    #stdout_gitcheckout, stderr_gitcheckout = Popen(['cd','/mnt/action/'+ str(action["id"]),'&&', 'git checkout ' + str(action["branch"])], stdout=PIPE).communicate()
    stdout, stderr = Popen(['git','checkout' , str(action["branch"])], stdout=PIPE, cwd='/home/for_agent/action/'+ str(action["id"]), stderr=PIPE).communicate()
    full_stdout += str(stdout.decode('utf-8'))
    full_stderr += str(stderr.decode('utf-8'))

    print("execute action %s"%action)
    stdout, stderr = Popen(['/home/for_agent/action/' + str(action["id"]) + "/"+ str(action["source_path"]) + str(action["source_run_file"])], stdout=PIPE, stderr=PIPE).communicate(timeout=action_timeout)
    #print(str(stdout.decode('utf-8')))
    #print(str(stderr.decode('utf-8')))

    full_stdout += str(stdout.decode('utf-8'))
    full_stderr += str(stderr.decode('utf-8'))

    print(full_stdout, full_stderr)

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
    print("Authorization: %s"%authorization)
    #headers = {"Authorization": authorization}
    #data ={}
    #response = requests.get("%s/users/me"%BACK, headers=headers, json=data)
    #print("Status Code", response.status_code)
    #print("JSON Response ", response.json())

    headers = {"Content-Type": "application/json", "Authorization": authorization}
    data ={"host_id":HOST_UUID}
    response = requests.post("%s/back/host-bind"%BACK, headers=headers, json=data)
    print("Status Code", response.status_code)
    print("JSON Response ", response.json())

    try:
        user_id = response.json()["id"]
        print(user_id)
        try:
            q = {"key": "authorized_user"}
            auth_users=a.getByQuery(query=q)
            if len(auth_users) == 0:
                a.add({"value":str(user_id),"key":"authorized_user","chapter":"host","name":"","type":"","vm_id":""})
                #return {"Detail": "Success binded"}
                return {"message": "OK"}
            else:
                record_id=a.getByQuery(query=q)[0]["id"]
                is_deleted = a.deleteById(pk=record_id)
                print(is_deleted)
                a.add({"value":str(user_id),"key":"authorized_user","chapter":"host","name":"","type":"","vm_id":""})
                return {"message":"OK","Detail":"Already binded(rebind for current) / " + str(response.json()["message"])}
        except Exception as inst:
            print(inst)
    except:
        print("Detail:Unauthorized")
        return {"message":"Unauthorized"}
    return {"message":"Unauthorized"}

@app.get("/agent/unbind", tags=["bind"])
async def unbind_host(authorization: Union[str, None] = Header(default=None)):
    print("Authorization: %s"%authorization)
    #headers = {"Authorization": authorization}
    #data ={}
    #response = requests.get("%s/users/me"%BACK, headers=headers, json=data)
    #print("Status Code", response.status_code)
    #print("JSON Response ", response.json())

    headers = {"Content-Type": "application/json", "Authorization": authorization}
    data ={"host_id":HOST_UUID}
    response = requests.post("%s/back/host-unbind"%BACK, headers=headers, json=data)
    print("Status Code", response.status_code)
    print("JSON Response ", response.json())
    try:
        if response.json()["message"] == "OK":
            try:
                q = {"key": "authorized_user"}
                auth_users=a.getByQuery(query=q)
                if len(auth_users) == 0:
                    return {"message": "OK", "Detail":"In host BD missing"}
                else:
                    record_id=a.getByQuery(query=q)[0]["id"]
                    is_deleted = a.deleteById(pk=record_id)
                    print(is_deleted)
                    return {"message":"OK"}
            except Exception as inst:
                print(inst)    
        else:
            return {"message":str(response.json()["message"])}
            
        # 
        # user_id = response.json()["id"]
        # print(user_id)
        # try:
        #     q = {"key": "authorized_user"}
        #     auth_users=a.getByQuery(query=q)
        #     if len(auth_users) == 0:
        #         #a.add({"value":str(user_id),"key":"authorized_user"},"chapter":"host","name":"","type":"","vm_id":"")
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
        print("Detail:Unauthorized")
        return {"message":"Unauthorized"}
    return {"message":"Unauthorized"}


@app.post("/agent/action", tags=["action"])
#async def start_action(authorization: Union[str, None] = Header(default=None), action: Action):
async def start_action(action: Action, authorization: Union[str, None] = Header(default=None)):
    print("Authorization: %s"%authorization)
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
    print("Status Code", response.status_code)
    print("JSON Response ", response.json())

    allowedExecution = response.json()["allowedExecution"]

    #Variables for export to Enviroment
    #for env_for_export in action.environment_variables:
    #    print("%s %s"%(env_for_export.name, env_for_export.value) )


    if allowedExecution=="True":
        if (action.environment_variables):
            print(action.environment_variables)
            await add_environment_variables(action.environment_variables)
        print(action.action_id)
        data={"action_id": action.action_id}
        #print("DATA: %s"%data)
        response_action = requests.post("%s/action"%BACK, headers=headers, json=data)
        print("Status Code", response_action.status_code)
        print("JSON Response ", response_action.json())
        print(response_action.json().keys())
        # Add ports 
        if "ports" in response_action.json().keys():
            if response_action.json()["ports"] != None:
                for port_add in response_action.json()["ports"]:
                    print(port_add)
                    # Проверка наличия порта в локальной базе и добавление если его нет, а если есть обновление данных(удаление и добавление по новой):
                    try:
                        q = {"key": "port", "value": port_add["value"], "vm_id": port_add["vm_id"]}
                        port_db=a.getByQuery(query=q)
                        if len(port_db) == 0:
                            #Добавляем порт в локальную базу так как его нет
                            a.add({"value":str(port_add["value"]),"key":"port","chapter":"host","name":str(port_add["name"]),"type":str(port_add["type"]),"vm_id":str(port_add["vm_id"])})
                        else:
                            #Если порт есть, удаляем его и его данные и добавляем по новой, для обновления записи. Почему не апдейт? Да хрен знает.
                            record_id=a.getByQuery(query=q)[0]["id"]
                            is_deleted = a.deleteById(pk=record_id)
                            print(is_deleted)
                            a.add({"value":str(port_add["value"]),"key":"port","chapter":"host","name":str(port_add["name"]),"type":str(port_add["type"]),"vm_id":str(port_add["vm_id"])})
                    except Exception as inst:
                        print(inst)    
                # Добавление всех портов в данные по хосту и отправка нового набора
                # Запрос всех портов в локальной БД
                q = {"key": "port"}
                port_db=a.getByQuery(query=q)
                port_on_sent=[]

                print(port_db)
                for port_one in port_db:
                    tmp_port = {"name":port_one["name"],"type_port":port_one["type"],"value":port_one["value"],"vm_id":port_one["vm_id"] }
                    port_on_sent.append(tmp_port)

                q = {"key": "authorized_user"}
                auth_users=a.getByQuery(query=q)
                if len(auth_users) == 0:
                    auth_user_on_sent = ""
                else:
                    auth_user_on_sent = auth_users[0]["value"]
                print(auth_users)
                headers = {"Content-Type": "application/json", "Authorization": authorization}
                data ={"host_id":HOST_UUID, "authorized_user":auth_user_on_sent,"ports":port_on_sent}
                response = requests.post("%s/back/ports-update"%BACK, headers=headers, json=data)
                print("Status Code", response.status_code)
                print("JSON Response ", response.json())
                



                    
        print("Start Action")
        full_stdout, full_stderr = await action_execute(response_action.json())
        return {"Detail":"Execute action", "full_stdout": full_stdout, "full_stderr": full_stderr}
    else:
        return {"Detail":"Execute action denied"}
        

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

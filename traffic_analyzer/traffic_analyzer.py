import argparse
import json
import requests
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
import sys

def load_model():
    base_model = "mistralai/Mistral-7B-v0.1"
    tokenizer = AutoTokenizer.from_pretrained(base_model)
    tokenizer.add_special_tokens({"pad_token": "[PAD]"})
    base_model = AutoModelForCausalLM.from_pretrained(base_model)
    ft_model = PeftModel.from_pretrained(base_model, "./qlora-out") 
    ft_model.eval()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    ft_model.to(device)
    return ft_model, tokenizer, device


def process_traffic_data(model, tokenizer, device, input_data):
    user_input = f"[INST] ###instruction: Check if the given traffic flow is normal or of an attacker or a victim\n###input: {input_data}\n#output: [/INST]"
    encodings = tokenizer(user_input, return_tensors="pt", padding=True).to(device)
    input_ids = encodings["input_ids"]
    attention_mask = encodings["attention_mask"]

    output_ids = model.generate(input_ids, attention_mask=attention_mask, max_new_tokens=1000, num_return_sequences=1, do_sample=True, temperature=0.1, top_p=0.9)
    generated_ids = output_ids[0, input_ids.shape[-1]:]
    response = tokenizer.decode(generated_ids, skip_special_tokens=True).lower()

    if "normal" in response:
        return "normal"
    elif "attacker" in response:
        return "attacker"
    elif "victim" in response:
        return "victim"
    else:
        return "unknown"


def authenticate(user, password, host):
    url = f"https://{host}:55000/security/user/authenticate"
    response = requests.post(url, auth=(user, password), verify=False)
    response_data = response.json()
    if response.status_code == 200 and 'data' in response_data and 'token' in response_data['data']:
        return response_data['data']['token']
    else:
        raise Exception("Authentication failed")


def send_to_wazuh(host, token, events):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }
    payload = {
        "events": events
    }
    url = f"https://{host}:55000/events"
    response = requests.post(url, headers=headers, json=payload, verify=False)
    return response.status_code, response.text


def write_requests_to_file(requests, filename):
    with open(filename, 'w') as file:
        json.dump(requests, file, indent=4)


def read_requests_from_file(filename):
    with open(filename, 'r') as file:
        return json.load(file)

def main():
    parser = argparse.ArgumentParser(description='Script para procesar tráfico de red y enviar resultados a Wazuh.')

    # Opciones
    subparsers = parser.add_subparsers(dest='command', help='Sub-comando a ejecutar')

    # Opciones API
    parser_send = subparsers.add_parser('send', help='Procesa el tráfico y envía los resultados a la API')
    parser_send.add_argument('input_file', help='Fichero de entrada con el tráfico de red')
    parser_send.add_argument('user', help='Usuario para autenticarse en la API de Wazuh')
    parser_send.add_argument('password', help='Contraseña para autenticarse en la API de Wazuh')
    parser_send.add_argument('host', help='IP del host de Wazuh')

    # Opciones fichero
    parser_save = subparsers.add_parser('save', help='Procesa el tráfico y guarda las requests en un fichero')
    parser_save.add_argument('input_file', help='Fichero de entrada con el tráfico de red')
    parser_save.add_argument('output_file', help='Fichero de salida para guardar las requests')

    # Opciones Fichero a API
    parser_sendfile = subparsers.add_parser('sendfile', help='Lee las requests de un fichero y las envía a la API')
    parser_sendfile.add_argument('input_file', help='Fichero de entrada con las requests')
    parser_sendfile.add_argument('user', help='Usuario para autenticarse en la API de Wazuh')
    parser_sendfile.add_argument('password', help='Contraseña para autenticarse en la API de Wazuh')
    parser_sendfile.add_argument('host', help='IP del host de Wazuh')

    
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if args.command == 'send':
        model, tokenizer, device = load_model()
        token = authenticate(args.user, args.password, args.host)
        events = []
        with open(args.input_file, 'r') as f:
            for line in f:
                data = json.loads(line)
                response = process_traffic_data(model, tokenizer, device, data["input"])
                if response in ["attacker", "victim"]:
                    event = json.dumps({
                        "input": data["input"],
                        "output": response
                    })
                    events.append(event)
                    if len(events) == 100:  
                        status_code, response_text = send_to_wazuh(args.host, token, events)
                        print(f'Response: {status_code}, {response_text}')
                        events = []
        if events:  
            status_code, response_text = send_to_wazuh(args.host, token, events)
            print(f'Response: {status_code}, {response_text}')

    elif args.command == 'save':
        model, tokenizer, device = load_model()
        requests_list = []
        with open(args.input_file, 'r') as f:
            for line in f:
                data = json.loads(line)
                response = process_traffic_data(model, tokenizer, device, data["input"])
                if response in ["attacker", "victim"]:
                    event = json.dumps({
                        "input": data["input"],
                        "output": response
                    })
                    requests_list.append(event)
        write_requests_to_file(requests_list, args.output_file)

    elif args.command == 'sendfile':
        token = authenticate(args.user, args.password, args.host)
        requests = read_requests_from_file(args.input_file)
        events = []
        for request in requests:
            events.append(request)
            if len(events) == 100:  
                status_code, response_text = send_to_wazuh(args.host, token, events)
                print(f'Response: {status_code}, {response_text}')
                events = []
        if events:  
            status_code, response_text = send_to_wazuh(args.host, token, events)
            print(f'Response: {status_code}, {response_text}')

if __name__ == "__main__":
    main()
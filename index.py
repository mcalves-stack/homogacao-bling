import requests
import base64
import time

# Configurações iniciais
client_id = ''
client_secret = ''
refresh_token = ''

def get_new_access_token(refresh_token):
    credentials = f"{client_id}:{client_secret}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    token_headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': f'Basic {encoded_credentials}'
    }
    token_data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }
    token_response = requests.post(
        'https://www.bling.com.br/Api/v3/oauth/token',
        headers=token_headers,
        data=token_data
    )
    if token_response.status_code == 200:
        new_tokens = token_response.json()
        return new_tokens['access_token'], new_tokens['refresh_token']
    else:
        print("Failed to refresh token:", token_response.json())
        return None, None

start_time = time.time()

# Step 1: GET
access_token, refresh_token = get_new_access_token(refresh_token)
if not access_token:
    print("Failed to obtain access token.")
    exit()

headers = {'Authorization': f'Bearer {access_token}'}
response = requests.get(
    'https://api.bling.com.br/Api/v3/homologacao/produtos',
    headers=headers
)
print("GET Response Status Code:", response.status_code)
print("GET Response JSON:", response.json())
if response.status_code != 200:
    print("GET request failed.")
    exit()

data = response.json()['data']
hash_header = response.headers.get('x-bling-homologacao')

# Step 2: POST
print("O token aqui vai ser invalido teste, nesta etapa, atualizando o token denovo mais uma vez.")
access_token, refresh_token = get_new_access_token(refresh_token)
if not access_token:
    print("Failed to obtain access token.")
    exit()
headers['Authorization'] = f'Bearer {access_token}'

headers.update({'x-bling-homologacao': hash_header})
product_data = {
    "nome": data['nome'],
    "preco": data['preco'],
    "codigo": data['codigo']
}

response = requests.post(
    'https://api.bling.com.br/Api/v3/homologacao/produtos',
    headers=headers,
    json=product_data
)
print("POST Response Status Code:", response.status_code)
print("POST Response JSON:", response.json())

if response.status_code in [200, 201]:
    response_json = response.json()
    if 'data' in response_json:
        product_id = response_json['data']['id']
        hash_header = response.headers.get('x-bling-homologacao')
        print(f"Product criado com sucesso com o ID: {product_id}")
    else:
        print("Unexpected response format:", response_json)
        exit()
else:
    print(f"POST request failed with status code {response.status_code}: {response.text}")
    exit()

# Step 3: PUT
updated_product_data = {
    "nome": "Copo",
    "preco": data['preco'],
    "codigo": data['codigo']
}
headers['x-bling-homologacao'] = hash_header

response = requests.put(
    f'https://api.bling.com.br/Api/v3/homologacao/produtos/{product_id}',
    headers=headers,
    json=updated_product_data
)
print("PUT Response Status Code:", response.status_code)

if response.status_code == 200:
    print("Product atualizado com sucesso.")
    hash_header = response.headers.get('x-bling-homologacao')
elif response.status_code == 204:
    print("Produto atualizado com sucesso.")
    hash_header = response.headers.get('x-bling-homologacao')
else:
    print(f"PUT request failed with status code {response.status_code}: {response.text}")
    exit()

# Step 4: PATCH
situation_data = {"situacao": "I"}
headers['x-bling-homologacao'] = hash_header

response = requests.patch(
    f'https://api.bling.com.br/Api/v3/homologacao/produtos/{product_id}/situacoes',
    headers=headers,
    json=situation_data
)
print("PATCH Response Status Code:", response.status_code)

if response.status_code == 200:
    print("Situação do produto atualizado com sucesso.")
    hash_header = response.headers.get('x-bling-homologacao')
elif response.status_code == 204:
    print("Situação do produto atualizado com sucesso.")
    hash_header = response.headers.get('x-bling-homologacao')
else:
    print(f"PATCH request failed with status code {response.status_code}: {response.text}")
    exit()

# Step 5: DELETE
headers['x-bling-homologacao'] = hash_header

response = requests.delete(
    f'https://api.bling.com.br/Api/v3/homologacao/produtos/{product_id}',
    headers=headers
)
print("DELETE Response Status Code:", response.status_code)

if response.status_code == 200:
    print("Produto deletado com sucesso.")
elif response.status_code == 204:
    print("Produto deletado com sucesso.")
else:
    print(f"DELETE request failed with status code {response.status_code}: {response.text}")
    exit()

end_time = time.time()
total_time = end_time - start_time
print(f"Total execution time: {total_time} seconds")
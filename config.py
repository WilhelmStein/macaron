import web3

def load_env():
    # import env
    with open('../.env') as f:
        for a in f:
            a = a.strip()
            if a.startswith('//'):
                continue
            a = [w.strip() for w in a.split('=')]
            try:
                a[1] = int(a[1])
            except ValueError:
                pass
            globals()[a[0]] = a[1]

# load_env()

api = web3.Web3(web3.providers.HTTPProvider(
    f'http://127.0.0.1:8545', request_kwargs={'timeout': 60})
)
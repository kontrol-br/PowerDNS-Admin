from flask import Blueprint, request
from powerdnsadmin.models.domain import Domain
from powerdnsadmin.lib.auth import dyndns_basic_auth
from powerdnsadmin.models.record import Record as RecordAPI

dyndns = Blueprint('dyndns', __name__)

@dyndns.route('/nic/update', methods=['GET'])
@dyndns_basic_auth
def update():
    hostname = request.args.get('hostname')
    new_ip = request.args.get('myip') or request.remote_addr
    comment = request.args.get('comment', '')

    if not hostname:
        return "nohost", 400

    # Obtem domínio base (ex: sub.exemplo.com → exemplo.com)
    domain_name = '.'.join(hostname.split('.')[-2:])
    domain = Domain.query.filter(Domain.name == domain_name).first()
    if not domain:
        return "nohost", 404

    fqdn = hostname if hostname.endswith('.') else hostname + '.'

    # Constrói rrset para envio via API
    rrset = {
        "name": fqdn,
        "type": "A",
        "ttl": 300,
        "changetype": "REPLACE",
        "records": [
            {
                "content": new_ip,
                "disabled": False
            }
        ]
    }

    if comment:
        rrset["comments"] = [
            {
                "content": comment,
                "account": "dyndns"
            }
        ]

    # Envia atualização para o PowerDNS
    r = RecordAPI().add(domain_name, rrset)

    if "error" in r:
        return f"911 {r['error']}", 500

    return f"good {new_ip}"

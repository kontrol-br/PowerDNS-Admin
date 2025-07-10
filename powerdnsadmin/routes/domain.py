import re
import json
import datetime
import traceback
import dns.name
import dns.reversename
import time
from  ..models.record import RecordDB
from distutils.version import StrictVersion
from flask import Blueprint, render_template, make_response, url_for, current_app, request, redirect, abort, jsonify, g, session
from flask_login import login_required, current_user, login_manager
from datetime import datetime, timedelta
from ..models.record import Record                # Objeto para comunicação com a API do PowerDNS

from ..lib.utils import pretty_domain_name
from ..lib.utils import pretty_json
from ..lib.utils import to_idna
from ..decorators import can_create_domain, operator_role_required, can_access_domain, can_configure_dnssec, can_remove_domain
from ..models.user import User, Anonymous
from ..models.account import Account
from ..models.setting import Setting
from ..models.history import History
from ..models.domain import Domain
from ..models.record_entry import RecordEntry
from ..models.domain_template import DomainTemplate
from ..models.domain_template_record import DomainTemplateRecord
from ..models.domain_setting import DomainSetting
from ..models.base import db
from ..models.domain_user import DomainUser
from ..models.account_user import AccountUser
from .admin import extract_changelogs_from_history
from ..decorators import history_access_required
domain_bp = Blueprint('domain',
                      __name__,
                      template_folder='templates',
                      url_prefix='/domain')


def generate_serial():
    return int(datetime.utcnow().strftime('%Y%m%d01'))




@domain_bp.before_request
def before_request():
    # Check if user is anonymous
    g.user = current_user
    login_manager.anonymous_user = Anonymous

    # Check site is in maintenance mode
    maintenance = Setting().get('maintenance')
    if maintenance and current_user.is_authenticated and current_user.role.name not in [
            'Administrator', 'Operator'
    ]:
        return render_template('maintenance.html')

    # Manage session timeout
    session.permanent = True
    current_app.permanent_session_lifetime = timedelta(
        minutes=int(Setting().get('session_timeout')))
    session.modified = True



@domain_bp.route('/<path:domain_name>', methods=['GET'])
@login_required
@can_access_domain
def domain(domain_name):
    # Verifica se a zona existe localmente
    domain = Domain.query.filter(Domain.name == domain_name).first()
    if not domain:
        abort(404)

    # Configurações globais do sistema
    quick_edit = Setting().get('record_quick_edit')
    records_allow_to_edit = Setting().get_records_allow_to_edit()
    forward_records_allow_to_edit = Setting().get_supported_record_types(Setting().ZONE_TYPE_FORWARD)
    reverse_records_allow_to_edit = Setting().get_supported_record_types(Setting().ZONE_TYPE_REVERSE)
    ttl_options = Setting().get_ttl_options()
    pretty_v6 = Setting().get('pretty_ipv6_ptr')

    # Busca registros conforme permissão do usuário
    if current_user.role.name in ['Administrator', 'Operator']:
        records_db = RecordDB.query.filter_by(domain_id=domain.id).all()
    else:
        records_db = RecordDB.query.filter_by(domain_id=domain.id, owner_id=current_user.id).all()

    records = []
    for r in records_db:
        # Oculta tipos de registros não permitidos (inclui SOA)
        if r.type.upper() not in records_allow_to_edit:
            continue

        r_name = r.name.rstrip('.')

        # Suporte à reversão de PTR se ativado
        if pretty_v6 and r.type == 'PTR' and 'ip6.arpa' in r_name and '*' not in r_name:
            try:
                r_name = dns.reversename.to_address(dns.name.from_text(r_name))
            except Exception:
                pass

        # Concatena prioridade para MX e SRV para mostrar corretamente
        if r.type in ['MX', 'SRV'] and r.prio is not None:
            content = f"{r.prio} {r.content}"
        else:
            content = r.content

        # Cria entrada de exibição
        record_entry = RecordEntry(
            name=r_name,
            type=r.type,
            status='Disabled' if r.disabled else 'Active',
            ttl=r.ttl,
            data=content,
            comment='',  # Comentários desativados no momento
            is_allowed_edit=True
        )
        records.append(record_entry)

    # Determina se é zona reversa
    if not re.search(r'ip6\.arpa|in-addr\.arpa$', domain_name):
        editable_records = forward_records_allow_to_edit
    else:
        editable_records = reverse_records_allow_to_edit

    # Restringe tipos de registros se o usuário não for dono e não for admin/op
    if current_user.role.name not in ['Administrator', 'Operator'] and domain.owner_id != current_user.id:
        editable_records = [r for r in editable_records if r in ['A', 'AAAA', 'CNAME']]

    return render_template(
        'domain.html',
        domain=domain,
        records=records,
        editable_records=editable_records,
        quick_edit=quick_edit,
        ttl_options=ttl_options,
        current_user=current_user,
        allow_user_view_history=Setting().get('allow_user_view_history')
    )









@domain_bp.route('/remove', methods=['GET', 'POST'])
@login_required
@can_remove_domain
def remove():
    # domains is a list of all the domains a User may access
    # Admins may access all
    # Regular users only if they are associated with the domain
    if current_user.role.name in ['Administrator', 'Operator']:
        domains = Domain.query.order_by(Domain.name).all()
    else:
        # Mostrar apenas as zonas onde o usuário é dono
        domains = Domain.query.filter_by(owner_id=current_user.id).order_by(Domain.name).all()

    if request.method == 'POST':
        domain_name = request.form['domainid']

        # Get domain from Database, might be None
        domain = Domain.query.filter(Domain.name == domain_name).first()

        # Check if the domain is in domains before removal
        if domain not in domains:
            abort(403)

        # Delete
        d = Domain()
        result = d.delete(domain_name)

        if result['status'] == 'error':
            abort(500)

        history = History(msg='Delete zone {0}'.format(
            pretty_domain_name(domain_name)),
                          created_by=current_user.username)
        history.add()

        return redirect(url_for('dashboard.dashboard'))

    else:
        return render_template('domain_remove.html', domainss=domains)








@domain_bp.route('/<path:domain_name>/changelog', methods=['GET'])
@login_required
@can_access_domain
@history_access_required
def changelog(domain_name):
    g.user = current_user
    login_manager.anonymous_user = Anonymous
    domain = Domain.query.filter(Domain.name == domain_name).first()
    if not domain:
        abort(404)

    # get all changelogs for this domain, in descening order
    if current_user.role.name in [ 'Administrator', 'Operator' ]:
        histories = History.query.filter(History.domain_id == domain.id).order_by(History.created_on.desc()).all()
    else:
        # if the user isn't an administrator or operator,
        # allow_user_view_history must be enabled to get here,
        # so include history for the domains for the user
        histories = db.session.query(History) \
            .join(Domain, History.domain_id == Domain.id) \
            .outerjoin(DomainUser, Domain.id == DomainUser.domain_id) \
            .outerjoin(Account, Domain.account_id == Account.id) \
            .outerjoin(AccountUser, Account.id == AccountUser.account_id) \
            .order_by(History.created_on.desc()) \
            .filter(
                db.and_(db.or_(
                                DomainUser.user_id == current_user.id,
                                AccountUser.user_id == current_user.id
                        ),
                        History.domain_id == domain.id,
                        History.detail.isnot(None)
                )
            ).all()

    changes_set = extract_changelogs_from_history(histories)

    return render_template('domain_changelog.html', domain=domain, allHistoryChanges=changes_set)

"""
Returns a changelog for a specific pair of (record_name, record_type)
"""
@domain_bp.route('/<path:domain_name>/changelog/<path:record_name>/<string:record_type>', methods=['GET'])
@login_required
@can_access_domain
@history_access_required
def record_changelog(domain_name, record_name, record_type):

    g.user = current_user
    login_manager.anonymous_user = Anonymous
    domain = Domain.query.filter(Domain.name == domain_name).first()
    if not domain:
        abort(404)

    # get all changelogs for this domain, in descening order
    if current_user.role.name in [ 'Administrator', 'Operator' ]:
        histories = History.query \
            .filter(
                db.and_(
                        History.domain_id == domain.id,
                        History.detail.like("%{}%".format(record_name))
                )
            ) \
            .order_by(History.created_on.desc()) \
            .all()
    else:
        # if the user isn't an administrator or operator, 
        # allow_user_view_history must be enabled to get here,
        # so include history for the domains for the user
        histories = db.session.query(History) \
            .join(Domain, History.domain_id == Domain.id) \
            .outerjoin(DomainUser, Domain.id == DomainUser.domain_id) \
            .outerjoin(Account, Domain.account_id == Account.id) \
            .outerjoin(AccountUser, Account.id == AccountUser.account_id) \
            .filter(
                db.and_(db.or_(
                                DomainUser.user_id == current_user.id,
                                AccountUser.user_id == current_user.id
                        ), 
                        History.domain_id == domain.id,
                        History.detail.like("%{}%".format(record_name))
                )
            ) \
            .order_by(History.created_on.desc()) \
            .all()

    changes_set = extract_changelogs_from_history(histories, record_name, record_type)

    return render_template('domain_changelog.html', domain=domain, allHistoryChanges=changes_set,
                            record_name = record_name, record_type = record_type)






@domain_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'GET':
        accounts = Account.query.all()
        return render_template('domain_add.html', accounts=accounts)

    domain_name = request.form.get('domain_name', '').strip().lower()
    account_id = request.form.get('accountid')
    domain_type = request.form.get('radio_type', 'NATIVE').upper()

    if domain_name.endswith('.'):
        domain_name = domain_name[:-1]

    if not domain_name or not re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', domain_name):
        return render_template('errors/400.html', msg="Invalid domain name"), 400

    try:
        current_app.logger.debug(
            f"[ZONA RECEBIDA] name={domain_name}, type={domain_type}, account_id={account_id}, owner_id={current_user.id}"
        )

        if Domain.query.filter_by(name=domain_name).first():
            return render_template('errors/400.html', msg="Domain already exists"), 400

        now = datetime.utcnow()

        new_domain = Domain(
            name=domain_name,
            type=domain_type,
            serial=int(now.strftime('%Y%m%d01')),
            notified_serial=0,
            last_check=1,
            dnssec=0,
            account_id=account_id if account_id and account_id != "0" else None,
            owner_id=current_user.id
        )

        db.session.add(new_domain)
        db.session.flush()
        
        du = DomainUser(domain_id=new_domain.id, user_id=current_user.id)
        db.session.add(du)
        
        # Adiciona a zona também na tabela nativa 'domains' do PowerDNS (usado pelo daemon)
        from sqlalchemy import text
        db.session.execute(
            text("""
                INSERT INTO domains (id, name, type, last_check)
                VALUES (:id, :name, :type, :last_check)
            """),
            {
                "id": new_domain.id,
                "name": domain_name,
                "type": domain_type,
                "last_check": 1
            }
        )

        now_ts = int(now.timestamp())

        soa_record = RecordDB(
            name=domain_name,
            type='SOA',
            content=f'ns1.{domain_name} hostmaster.{domain_name} {now.strftime("%Y%m%d%H")} 10800 3600 604800 3600',
            ttl=3600,
            domain_id=new_domain.id,
            change_date=now_ts,
            prio=None,
            disabled=False,
            auth=True,
            owner_id=current_user.id
        )

        ns_record = RecordDB(
            name=domain_name,
            type='NS',
            content=f'ns1.{domain_name}',
            ttl=3600,
            domain_id=new_domain.id,
            change_date=now_ts,
            prio=None,
            disabled=False,
            auth=True,
            owner_id=current_user.id
        )

        db.session.add(soa_record)
        db.session.add(ns_record)
        db.session.commit()

        db.session.add(History(msg=f'Add new domain {domain_name}', created_by=current_user.username))
        db.session.commit()

        current_app.logger.info(f'Added new domain {domain_name}')
        return redirect(url_for('dashboard.dashboard'))

    except Exception as e:
        current_app.logger.error(f'Cannot add zone. Error: {e}')
        current_app.logger.debug(traceback.format_exc())
        return render_template('errors/400.html', msg="Failed to add domain."), 400










@domain_bp.route('/setting/<path:domain_name>/delete', methods=['POST'])
@login_required
@operator_role_required
def delete(domain_name):
    d = Domain()
    result = d.delete(domain_name)

    if result['status'] == 'error':
        abort(500)

    history = History(msg='Delete zone {0}'.format(
        pretty_domain_name(domain_name)),
                      created_by=current_user.username)
    history.add()

    return redirect(url_for('dashboard.dashboard'))


@domain_bp.route('/setting/<path:domain_name>/manage', methods=['GET', 'POST'])
@login_required
@operator_role_required
def setting(domain_name):
    if request.method == 'GET':
        domain = Domain.query.filter(Domain.name == domain_name).first()
        if not domain:
            abort(404)
        users = User.query.all()
        accounts = Account.query.order_by(Account.name).all()

        # get list of user ids to initialize selection data
        d = Domain(name=domain_name)
        domain_user_ids = d.get_user()
        account = d.get_account()
        domain_info = d.get_domain_info(domain_name)

        return render_template('domain_setting.html',
                               domain=domain,
                               users=users,
                               domain_user_ids=domain_user_ids,
                               accounts=accounts,
                               domain_account=account,
                               zone_type=domain_info["kind"].lower(),
                               masters=','.join(domain_info["masters"]),
                               soa_edit_api=domain_info["soa_edit_api"].upper())

    if request.method == 'POST':
        # username in right column
        new_user_list = request.form.getlist('domain_multi_user[]')
        new_user_ids = [
            user.id for user in User.query.filter(
                User.username.in_(new_user_list)).all() if user
        ]

        # grant/revoke user privileges
        d = Domain(name=domain_name)
        d.grant_privileges(new_user_ids)

        history = History(
            msg='Change zone {0} access control'.format(
                pretty_domain_name(domain_name)),
            detail=json.dumps({'user_has_access': new_user_list}),
            created_by=current_user.username,
            domain_id=d.id)
        history.add()

        return redirect(url_for('domain.setting', domain_name=domain_name))


@domain_bp.route('/setting/<path:domain_name>/change_type',
                 methods=['POST'])
@login_required
@operator_role_required
def change_type(domain_name):
    domain = Domain.query.filter(Domain.name == domain_name).first()
    if not domain:
        abort(404)
    domain_type = request.form.get('domain_type')
    if domain_type is None:
        abort(500)
    if domain_type == '0':
        return redirect(url_for('domain.setting', domain_name=domain_name))

    #TODO: Validate ip addresses input
    domain_master_ips = []
    if domain_type == 'slave' and request.form.getlist('domain_master_address'):
        domain_master_string = request.form.getlist(
            'domain_master_address')[0]
        domain_master_string = domain_master_string.replace(
            ' ', '')
        domain_master_ips = domain_master_string.split(',')

    d = Domain()
    status = d.update_kind(domain_name=domain_name,
                           kind=domain_type,
                           masters=domain_master_ips)
    if status['status'] == 'ok':
        history = History(msg='Update type for zone {0}'.format(
                pretty_domain_name(domain_name)),
                          detail=json.dumps({
                              "domain": domain_name,
                              "type": domain_type,
                              "masters": domain_master_ips
                          }),
                          created_by=current_user.username,
                          domain_id=Domain().get_id_by_name(domain_name))
        history.add()
        return redirect(url_for('domain.setting', domain_name = domain_name))
    else:
        abort(500)


@domain_bp.route('/setting/<path:domain_name>/change_soa_setting',
                 methods=['POST'])
@login_required
@operator_role_required
def change_soa_edit_api(domain_name):
    domain = Domain.query.filter(Domain.name == domain_name).first()
    if not domain:
        abort(404)
    new_setting = request.form.get('soa_edit_api')
    if new_setting is None:
        abort(500)
    if new_setting == '0':
        return redirect(url_for('domain.setting', domain_name=domain_name))

    d = Domain()
    status = d.update_soa_setting(domain_name=domain_name,
                                  soa_edit_api=new_setting)
    if status['status'] == 'ok':
        history = History(
            msg='Update soa_edit_api for zone {0}'.format(
                pretty_domain_name(domain_name)),
            detail = json.dumps({
                'domain': domain_name,
                'soa_edit_api': new_setting
            }),
            created_by=current_user.username,
            domain_id=d.get_id_by_name(domain_name))
        history.add()
        return redirect(url_for('domain.setting', domain_name = domain_name))
    else:
        abort(500)


@domain_bp.route('/setting/<path:domain_name>/change_account',
                 methods=['POST'])
@login_required
@operator_role_required
def change_account(domain_name):
    domain = Domain.query.filter(Domain.name == domain_name).first()
    if not domain:
        abort(404)

    account_id = request.form.get('accountid')
    status = Domain(name=domain.name).assoc_account(account_id)
    if status['status']:
        return redirect(url_for('domain.setting', domain_name=domain.name))
    else:
        abort(500)




@domain_bp.route('/<path:domain_name>/apply', methods=['POST'])
@login_required
@can_access_domain
def record_apply(domain_name):
    try:
        import time
        jdata = request.json
        submitted_serial = jdata['serial']
        submitted_records = jdata['record']

        current_app.logger.debug(f"[INPUT RECEBIDO] {submitted_records}")

        domain = Domain.query.filter(Domain.name == domain_name).first()
        if not domain:
            return jsonify({'status': 'error', 'msg': 'Domain not found'}), 404

        new_records = []

        for record_data in submitted_records:
            current_app.logger.debug(f"[REGISTRO RECEBIDO] {record_data}")
            rec_name = record_data['record_name'].strip().strip('.')
            rec_type = record_data['record_type'].strip().upper()
            rec_status = record_data['record_status']
            rec_ttl = int(record_data['record_ttl'])
            rec_data = record_data['record_data'].strip()
            rec_comment = record_data.get('record_comment', '').strip()
            
            # FQDN sem ponto final no final
            if rec_name in ['', '@']:
                fqdn = domain_name
            elif rec_name.endswith(domain_name):
                fqdn = rec_name
            else:
                fqdn = f"{rec_name}.{domain_name}"
            fqdn = fqdn.rstrip('.')  # remove ponto final, se houver

            current_app.logger.debug(f"[CALCULADO] record_name = {fqdn}")

            # Protege o SOA: nem modifica, nem deleta
            if rec_type == 'SOA':
                record_in_db = RecordDB.query.filter_by(domain_id=domain.id, name=fqdn, type='SOA').first()
                if not record_in_db:
                    current_app.logger.warning(f"[BLOQUEADO] Tentativa de criação de SOA por {current_user.username}")
                    return jsonify({
                        'status': 'error',
                        'msg': 'SOA record cannot be created manually.'
                    }), 400
                else:
                    current_app.logger.debug(f"[IGNORADO] SOA existente preservado: {fqdn}")
                    new_records.append(record_in_db)
                    continue

            current_app.logger.debug(f"[CHECK] Verificando duplicidade: ({fqdn}, {rec_type})")

            # Busca conflitos com o mesmo nome
            existing_conflict = RecordDB.query.filter(
                RecordDB.domain_id == domain.id,
                RecordDB.name == fqdn
            ).all()

            record = None
            for conflict in existing_conflict:
                if conflict.type == rec_type:
                    if current_user.role.name not in ['Administrator', 'Operator'] and conflict.owner_id != current_user.id:
                        current_app.logger.debug(
                            f"[DUPLICADO NO BANCO] Já existe: {fqdn} {rec_type} por outro usuário (owner_id={conflict.owner_id})"
                        )
                        return jsonify({
                            'status': 'error',
                            'msg': f'Record \"{fqdn}\" of type \"{rec_type}\" already exists and belongs to another user.'
                        }), 400
                    record = conflict
                    break
                else:
                    # Impede que usuários que não são donos nem administradores criem tipos diferentes para o mesmo nome
                    if current_user.role.name not in ['Administrator', 'Operator'] and domain.owner_id != current_user.id:
                        current_app.logger.debug(
                            f"[CONFLITO BLOQUEADO] {current_user.username} tentou criar tipo {rec_type} para {fqdn}, mas já existe tipo {conflict.type}"
                        )
                        return jsonify({
                            'status': 'error',
                            'msg': f'Cannot create record \"{fqdn}\" with type \"{rec_type}\" because it conflicts with existing type \"{conflict.type}\".'
                        }), 400

            if not record:
                record = RecordDB(domain_id=domain.id, name=fqdn, type=rec_type)

            record.content = rec_data
            record.ttl = rec_ttl
            if rec_type == 'MX':
                parts = rec_data.strip().split()
                if len(parts) >= 2 and parts[0].isdigit():
                    record.prio = int(parts[0])
                    record.content = ' '.join(parts[1:])
                elif record.prio is None:
                    current_app.logger.warning(f"[ERRO] Formato inválido para MX: {rec_data}")
                    return jsonify({
                        'status': 'error',
                        'msg': f'Invalid MX format. Expected: \"<priority> <target>\".'
                    }), 400
                else:
                    record.content = rec_data

            elif rec_type == 'SRV':
                parts = rec_data.strip().split()
                if len(parts) >= 4 and all(p.isdigit() for p in parts[:3]):
                    record.prio = int(parts[0])  # extrai apenas a prioridade
                    record.content = ' '.join(parts[1:])  # apenas weight, port e target vão para o content
                else:
                    current_app.logger.warning(f"[ERRO] Formato inválido para SRV: {rec_data}")
                    return jsonify({
                        'status': 'error',
                        'msg': f'Invalid SRV format. Expected: \"<priority> <weight> <port> <target>\".'
                    }), 400
            else:
                record.prio = None
                record.content = rec_data
            
            # Restrição de tipo para usuários comuns que não são donos da zona
            if current_user.role.name not in ['Administrator', 'Operator'] and domain.owner_id != current_user.id:
                allowed_types = ['A', 'AAAA', 'CNAME']
                if rec_type not in allowed_types:
                    current_app.logger.warning(
                        f"[TIPO NÃO PERMITIDO] {current_user.username} tentou criar tipo {rec_type} na zona {domain.name} sem permissão"
                    )
                    return jsonify({
                        'status': 'error',
                        'msg': f'Record type \"{rec_type}\" is not allowed. Only A, AAAA, and CNAME are permitted.'
                    }), 400

            if not record.id or current_user.role.name not in ['Administrator', 'Operator']:
                record.owner_id = current_user.id

            new_records.append(record)

        # Remover registros antigos do banco que não estão na nova lista (exceto SOA)
        all_existing_records = RecordDB.query.filter(RecordDB.domain_id == domain.id).all()
        to_keep = {(r.name, r.type) for r in new_records}
        for old in all_existing_records:
            if old.type == 'SOA':
                continue
            if (old.name, old.type) not in to_keep:
                if current_user.role.name in ['Administrator', 'Operator'] or old.owner_id == current_user.id:
                    db.session.delete(old)
                else:
                    current_app.logger.debug(f"[BLOQUEADO] {current_user.username} tentou deletar record de outro usuário: {old.name} ({old.type})")

        for r in new_records:
            r.change_date = int(time.time())
            db.session.add(r)
            
        domain.change_date = int(time.time())
        db.session.add(domain)

        db.session.commit()
        return jsonify({'status': 'ok', 'msg': 'Records applied successfully'})

    except Exception as e:
        current_app.logger.error(f"Error applying record: {e}")
        return jsonify({'status': 'error', 'msg': f'Error applying record: {e}'}), 500











@domain_bp.route('/<path:domain_name>/update',
                 methods=['POST'],
                 strict_slashes=False)
@login_required
@can_access_domain
def record_update(domain_name):
    """
    This route is used for zone work as Slave Zone only
    Pulling the records update from its Master
    """
    try:
        jdata = request.json

        domain_name = jdata['domain']
        d = Domain()
        result = d.update_from_master(domain_name)
        if result['status'] == 'ok':
            return make_response(
                jsonify({
                    'status': 'ok',
                    'msg': result['msg']
                }), 200)
        else:
            return make_response(
                jsonify({
                    'status': 'error',
                    'msg': result['msg']
                }), 500)
    except Exception as e:
        current_app.logger.error('Cannot update record. Error: {0}'.format(e))
        current_app.logger.debug(traceback.format_exc())
        return make_response(
            jsonify({
                'status': 'error',
                'msg': 'Error when applying new changes'
            }), 500)




@domain_bp.route('/<path:domain_name>/info', methods=['GET'])
@login_required
@can_access_domain
def info(domain_name):
    domain = Domain()
    domain_info = domain.get_domain_info(domain_name)

    # Recuperar o owner_id localmente do banco
    db_domain = Domain.query.filter_by(name=domain_name).first()
    if db_domain:
        domain_info['owner_id'] = db_domain.owner_id
    else:
        domain_info['owner_id'] = None

    return make_response(jsonify(domain_info), 200)





@domain_bp.route('/<path:domain_name>/dnssec', methods=['GET'])
@login_required
@can_access_domain
def dnssec(domain_name):
    domain = Domain()
    dnssec = domain.get_domain_dnssec(domain_name)
    return make_response(jsonify(dnssec), 200)


@domain_bp.route('/<path:domain_name>/dnssec/enable', methods=['POST'])
@login_required
@can_access_domain
@can_configure_dnssec
def dnssec_enable(domain_name):
    domain = Domain()
    dnssec = domain.enable_domain_dnssec(domain_name)
    domain_object = Domain.query.filter(domain_name == Domain.name).first()
    history = History(
        msg='DNSSEC was enabled for zone ' + domain_name ,
        created_by=current_user.username,
        domain_id=domain_object.id)
    history.add()
    return make_response(jsonify(dnssec), 200)


@domain_bp.route('/<path:domain_name>/dnssec/disable', methods=['POST'])
@login_required
@can_access_domain
@can_configure_dnssec
def dnssec_disable(domain_name):
    domain = Domain()
    dnssec = domain.get_domain_dnssec(domain_name)

    for key in dnssec['dnssec']:
        domain.delete_dnssec_key(domain_name, key['id'])
    domain_object = Domain.query.filter(domain_name == Domain.name).first()
    history = History(
        msg='DNSSEC was disabled for zone ' + domain_name ,
        created_by=current_user.username,
        domain_id=domain_object.id)
    history.add()
    return make_response(jsonify({'status': 'ok', 'msg': 'DNSSEC removed.'}))


@domain_bp.route('/<path:domain_name>/manage-setting', methods=['GET', 'POST'])
@login_required
@operator_role_required
def admin_setdomainsetting(domain_name):
    if request.method == 'POST':
        #
        # post data should in format
        # {'action': 'set_setting', 'setting': 'default_action, 'value': 'True'}
        #
        try:
            jdata = request.json
            data = jdata['data']

            if jdata['action'] == 'set_setting':
                new_setting = data['setting']
                new_value = str(data['value'])
                domain = Domain.query.filter(
                    Domain.name == domain_name).first()
                setting = DomainSetting.query.filter(
                    DomainSetting.domain == domain).filter(
                        DomainSetting.setting == new_setting).first()

                if setting:
                    if setting.set(new_value):
                        history = History(
                            msg='Setting {0} changed value to {1} for {2}'.
                            format(new_setting, new_value,
                                   pretty_domain_name(domain_name)),
                            created_by=current_user.username,
                            domain_id=domain.id)
                        history.add()
                        return make_response(
                            jsonify({
                                'status': 'ok',
                                'msg': 'Setting updated.'
                            }))
                    else:
                        return make_response(
                            jsonify({
                                'status': 'error',
                                'msg': 'Unable to set value of setting.'
                            }))
                else:
                    if domain.add_setting(new_setting, new_value):
                        history = History(
                            msg=
                            'New setting {0} with value {1} for {2} has been created'
                            .format(new_setting, new_value, pretty_domain_name(domain_name)),
                            created_by=current_user.username,
                            domain_id=domain.id)
                        history.add()
                        return make_response(
                            jsonify({
                                'status': 'ok',
                                'msg': 'New setting created and updated.'
                            }))
                    else:
                        return make_response(
                            jsonify({
                                'status': 'error',
                                'msg': 'Unable to create new setting.'
                            }))
            else:
                return make_response(
                    jsonify({
                        'status': 'error',
                        'msg': 'Action not supported.'
                    }), 400)
        except Exception as e:
            current_app.logger.error(
                'Cannot change zone setting. Error: {0}'.format(e))
            current_app.logger.debug(traceback.format_exc())
            return make_response(
                jsonify({
                    'status':
                    'error',
                    'msg':
                    'There is something wrong, please contact Administrator.'
                }), 400)

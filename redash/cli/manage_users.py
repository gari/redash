from __future__ import print_function

import random
import os
import string

import click
from click import argument, option

import yaml
from flask import current_app
from flask.cli import AppGroup
from redash.query_runner import query_runners
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import IntegrityError

from six import text_type


from redash import models
from redash.utils.configuration import ConfigurationContainer
from redash.utils import json_loads
from redash.cli.data_sources import validate_data_source_type
from redash.cli.users import build_groups
from redash.handlers.users import invite_user


manager = AppGroup(help="Manage users via yaml config")



@manager.command(name="yaml")
@argument("config")
@option(
    "--org",
    "organization",
    default="default",
    help="the organization the user belongs to, (leave blank for " "'default').",
)
def manage_from_yaml(config, organization="default"):
    '''
    Manage users via yaml config
    '''

    print('Try to read yaml file: {}'.format(config))

    with open(config) as f:
        dataMap = yaml.safe_load(f)

    print('{}'.format(dataMap))

    print("====== Datastores ======")
    for datastore in dataMap['datastores']:
        # print(datastore)
        print('=======')
        if check_datasource_exist(name=datastore['name']):
            # TODO: FIX
            update_datasource(name=datastore['name'])
        else:
            print("> Not exist datastore {}".format(datastore['name']))
            new_datasource(
                name=datastore['name'],
                type=datastore['type'],
                # organization='mr',
                values=datastore
            )

    print("====== Groups ======")
    for group in dataMap['groups']:
        if check_exist_group(name=group['name']):
            create_group(name=group['name'])

        check_groups_datastore(
            datastore_list=group['datastores'],
            group_name=group['name']
        )
    
    print("====== Users ======")
    current_app.config['SERVER_NAME'] = os.environ.get("REDASH_HOST")
    with current_app.test_request_context():
        if not user_exist(email=dataMap['inviter_user']['email']):
            create(
                email=dataMap['inviter_user']['email'],
                name=dataMap['inviter_user']['email'].split('@')[0],
                groups="admin",
                password=randomString(30),
                is_admin=True
            )

        user_list = []

        for user in dataMap['users']:
            user_list.append(user['email'])
            try:
                if user['admin'] == True:
                    print("ADMIN")
                user['group'] = ['default', 'admin']
            except KeyError:
                user['admin'] = False
            if not user_exist(email=user['email']):
                name = user['email'].split('@')[0]
                grp = ",".join(user['group'])
                print(grp)
                invite(
                    email=user['email'],
                    name=name,
                    groups=grp,
                    is_admin=user['admin'],
                    inviter_email=dataMap['inviter_user']['email']
                )
            else:
                # print(user['group'])
                check_users_groups(
                    email=user['email'],
                    groups=user['group']
                )

    print("====== Disable users ======")
    disable_users(user_list)

def disable_users(user_list, organization='default'):
    org = models.Organization.get_by_slug(organization)
    all_users = models.User.query.filter(
        models.User.org == org,
        models.User.disabled_at == None
        ).all()
    for u in all_users:
        if u.email not in user_list:
            print("> Allarm Try to disable user {}".format(u.email))
            u.disable()
            models.db.session.add(u)
            models.db.session.commit()



def check_users_groups(email, groups, organization='default'):
    print("> Check groups for user {}".format(email))
    org = models.Organization.get_by_slug(organization)
    user = models.User.query.filter(
        models.User.org == org,
        models.User.email == email
        ).one_or_none()
    # for i in user.group_ids:
    grp_from_config = models.Group.find_by_name(org, groups)
    real_group_id = user.group_ids
    print("group from config: {}".format(grp_from_config))
    # print("real_group_id: {}".format(real_group_id))
    real_group = []
    for i in real_group_id:
        real_group.append(models.Group.query.filter(
            models.Group.id == i
        ).one_or_none())
    
    # print(real_group)
    print("real group: {}".format(real_group))


    diff = list(set(real_group) - set(grp_from_config))
    diff2 = list(set(grp_from_config) - set(real_group))
    if len(diff) > 0 or len(diff2):
        print("> Update groups")
        new_grp = []
        for g in grp_from_config:
            gr = models.Group.query.filter(
                models.Group.id == g.id
            ).first()
            new_grp.append(gr.id) 
        user.group_ids = new_grp
        models.db.session.add(user)
        models.db.session.commit()
    

    # print(diff2)





def randomString(stringLength=8):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def create(
    email,
    name,
    groups,
    is_admin=False,
    password=None,
    organization="default",
):
    """
    Create user EMAIL with display name NAME.
    """
    print("Creating user (%s, %s) in organization %s..." % (email, name, organization))
    print("Admin: %r" % is_admin)

    org = models.Organization.get_by_slug(organization)
    groups = build_groups(org, groups, is_admin)

    user = models.User(org=org, email=email, name=name, group_ids=groups)
    if not password:
        password = prompt("Password", hide_input=True, confirmation_prompt=True)

    try:
        models.db.session.add(user)
        models.db.session.commit()
    except Exception as e:
        print("Failed creating user: %s" % e)
        exit(1)


def build_groups_fff(org, groups, is_admin):
    if isinstance(groups, str):
        groups_name = groups.split(',')
        print(groups_name)
        if ''  in groups_name:
            groups.remove('')  # in case it was empty string
        fff = []
        for name in groups_name:
            # print(name)
            gr = models.Group.query.filter(
                models.Group.name == name,
                models.Group.org == org
            ).first()
            fff.append(gr.id) 
        groups = [int(g) for g in fff]

    
    if groups is None:
        groups = [org.default_group.id]

    if is_admin:
        groups += [org.admin_group.id]

    return groups

def invite(email, name, inviter_email, groups, is_admin=False, organization="default"):
    """
    Sends an invitation to the given NAME and EMAIL from INVITER_EMAIL.
    """
    org = models.Organization.get_by_slug(organization)
    groups = build_groups_fff(org, groups, is_admin)
    try:
        user_from = models.User.get_by_email_and_org(inviter_email, org)
        user = models.User(org=org, name=name, email=email, group_ids=groups)
        models.db.session.add(user)
        try:
            models.db.session.commit()
            invite_user(org, user_from, user)
            print("An invitation was sent to [%s] at [%s]." % (name, email))
        except IntegrityError as e:
            if "email" in str(e):
                print("Cannot invite. User already exists [%s]" % email)
            else:
                print(e)
    except NoResultFound:
        print("The inviter [%s] was not found." % inviter_email)



def user_exist(email, organization='default'):
    '''                                                                                                                                                                                                                                                                                            
    true if user exist                                                                                                                                                                                                                                                                             
    '''
    org = models.Organization.get_by_slug(organization)
    try:                                                                                                                                                                                                                                                                                           
        user = models.User.get_by_email_and_org(email, org)
    except NoResultFound:                                                                                                                                                                                                                                                                          
        return False                                                                                                                                                                                                                                                                               
                                                                                                                                                                                                                                                                                                
    return True 

def check_groups_datastore(group_name=None, datastore_list=None, organization='default'):
    if group_name is None or datastore_list is None:
        print("> group_name is None or datastore_list is None")
        return False
    print("> Check datastores for group: {}".format(group_name))

    org = models.Organization.get_by_slug(organization)

    # data_source = models.DataSource.query.filter(
    #     models.Group.name == group_name,
    #     models.Group.org == org
    # ).all()
    group = models.Group.query.filter(
        models.Group.name == group_name,
        models.Group.org == org
    ).one_or_none()
    data_sources = models.DataSource.query.join(models.DataSourceGroup).filter(
        models.DataSourceGroup.group == group
    ).all()
    base_datasourse = []
    for d in data_sources:
        base_datasourse.append(d.name)

    for new_datasource in datastore_list:
        if new_datasource not in base_datasourse:
            try:
                assign_datastore_to_group(
                    group_name=group_name,
                    datastore_name=new_datasource
                )
            except NoResultFound:
                print("> ERROR NoResultFound for datastore {}".format(new_datasource))
    
    diff1 = list(set(base_datasourse) - set(datastore_list))
    diff2 = list(set(datastore_list) - set(base_datasourse))

    if len(diff1) > 0:
        print("> Found bad datasorse in group {}".format(group_name))
        for d in diff1:
            print("> Try to delete datastore {} for group {}".format(d, group_name))
            data_sources = models.DataSource.query.join(models.DataSourceGroup).filter(
                models.DataSourceGroup.group == group,
                models.Group.org == org,
                models.DataSource.name == d,
            ).one_or_none()

            data_sources.remove_group(group)

    if len(diff2) > 0:
        print("> Not Found datasorse in group {}".format(group_name))
        for d in diff2:
            print("> Try to add datastore {} for group {}".format(d, group_name))
            try:
                data_sources = models.DataSource.query.join(models.DataSourceGroup).filter(
                    models.DataSourceGroup.group == group,
                    models.Group.org == org,
                    models.DataSource.name == d,
                ).one_or_none()
                data_sources.add_group(group)
            except AttributeError as e:
                print("Error {} for {}".format(e, d))
                





def assign_datastore_to_group(group_name=None, datastore_name=None, organization='default'):
    if group_name is None or datastore_name is None:
        print("> group_name is None or datastore_name is None")
        return False

    org = models.Organization.get_by_slug(organization)
    group = models.Group.query.filter(
        models.Group.name == group_name,
        models.Group.org == org
    ).one_or_none()

    # print(group.id)

    data_source = models.DataSource.get_by_name(datastore_name)
    # print(data_source)
    # print(data_source.groups)
    if len(data_source.groups) > 0:
        for d in data_source.groups:
            if group.id == d:
                print('> Group {} already assigment to datastore "{}"'.format(
                    group_name, datastore_name
                ))
            else:
                data_source_group = data_source.add_group(group)
                models.db.session.commit()
    else:
        data_source_group = data_source.add_group(group)
        models.db.session.commit()




def create_group(name, permissions=None, organization='default'):
    print("Creating group (%s)..." % (name))

    org = models.Organization.get_by_slug(organization)

    permissions = extract_permissions_string(permissions)

    print("permissions: [%s]" % ",".join(permissions))

    try:
        models.db.session.add(models.Group(
            name=name, org=org,
            permissions=permissions))
        models.db.session.commit()
    except Exception as e:
        print("Failed create group: %s" % e.message)
        exit(1)

def extract_permissions_string(permissions):
    if permissions is None:
        permissions = models.Group.DEFAULT_PERMISSIONS
    else:
        permissions = permissions.split(',')
        permissions = [p.strip() for p in permissions]
    return permissions


def check_exist_group(name=None, organization='default'):
    '''
    check if group exists
    '''
    org = models.Organization.get_by_slug(organization)
    try:
        group = models.Group.query.filter(
            models.Group.name == name,
            models.Group.org == org
        ).one_or_none()
    except NoResultFound:
        print("Group name [%s] not found." %  name)
        return False
    if group is None:
        return True
    else:
        return False


def update_datasource(name, options=None, organization='default'):
    '''
    Update datastore
    '''
    # TODO: 
    print("> Update datastore " + name)
    print("> TODO: Update datastore " + name)


def check_datasource_exist(name=None, organization='default'):
    '''
    Check if datasourse exits
    '''
    if name == None:
        return False
    try:
        org = models.Organization.get_by_slug(organization)
        data_source = models.DataSource.query.filter(
            models.DataSource.name == name,
            models.DataSource.org == org).first()
        if data_source:
            return True
    except NoResultFound:
        print("> Couldn't find data source named: {}".format(name))
        return False
    
def new_datasource(name=None, type=None, options=None, values=None, organization='default'):
    """Create new data source."""

    if name is None:
        name = click.prompt("Name")

    if type is None:
        print("Select type:")
        for i, query_runner_name in enumerate(query_runners.keys()):
            print("{}. {}".format(i + 1, query_runner_name))

        idx = 0
        while idx < 1 or idx > len(query_runners.keys()):
            idx = click.prompt("[{}-{}]".format(1, len(query_runners.keys())),
                               type=int)

        type = query_runners.keys()[idx - 1]
    else:
        validate_data_source_type(type)

    query_runner = query_runners[type]
    schema = query_runner.configuration_schema()

    print('00000000')
    print(schema)

    if options is None:
        types = {
            'string': text_type,
            'number': int,
            'boolean': bool
        }

        options_obj = {}

        for k, prop in schema['properties'].items():
            required = k in schema.get('required', [])
            default_value = "<<DEFAULT_VALUE>>"
            if required:
                default_value = None

            prompt = prop.get('title', k.capitalize())
            # print(k)
            if k == 'url':
                options_obj[k]=values['url']
            if k == 'dbname':
                options_obj[k]=values['dbname']
            if k == 'password':
                options_obj[k]=values['password']
            if k == 'timeout':
                options_obj[k]=values['timeout']
            if k == 'user':
                options_obj[k]=values['user']

        print(options_obj)
        options = ConfigurationContainer(options_obj, schema)
    else:
        options = ConfigurationContainer(json_loads(options), schema)

    if not options.is_valid():
        print("Error: invalid configuration.")
        exit()

    print("Creating {} data source ({}) with options:\n{}".format(
        type, name, options.to_json()))

    data_source = models.DataSource.create_with_group(
        name=name, type=type, options=options,
        org=models.Organization.get_by_slug(organization))
    models.db.session.commit()
    print("Id: {}".format(data_source.id))


# def validate_data_source_type(type):
#     if type not in query_runners.keys():
#         print("Error: the type \"{}\" is not supported (supported types: {})."
#                .format(type, ", ".join(query_runners.keys())))
#         print("OJNK")
#         exit(1)

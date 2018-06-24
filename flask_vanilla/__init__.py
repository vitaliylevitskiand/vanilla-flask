from datetime import datetime, date
import unittest
from logging.config import dictConfig
from sqlalchemy import (
    Column as _Column, Boolean, Integer, String, DateTime,
    ForeignKey, UniqueConstraint, inspect, types,
    TypeDecorator
)
from sqlalchemy.orm import class_mapper, ColumnProperty, \
    validates, joinedload
from sqlalchemy.sql.expression import true
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.interfaces import MANYTOONE
from sqlalchemy.orm.relationships import RelationshipProperty
from flask_sqlalchemy import SQLAlchemy, BaseQuery
import json
from flask import jsonify, request, g, abort, Flask, current_app
from flask.json import JSONEncoder
from flask_cache import Cache
from flask_validator import (ValidateNumeric, ValidateInteger, ValidateLength,
                             ValidateString, Validator)

db = SQLAlchemy()
cache = Cache()


class ModelValidationError(Exception):
    def __init__(self, errors):
        self.errors = errors
        self.msg = 'Validation has been failed'


class QueryWithSoftDelete(BaseQuery):
    def __new__(cls, *args, **kwargs):
        obj = super(QueryWithSoftDelete, cls).__new__(cls)
        with_deleted = kwargs.pop('_with_deleted', False)
        if len(args) > 0:
            super(QueryWithSoftDelete, obj).__init__(*args, **kwargs)
            return obj.filter_by(deleted=False) if not with_deleted else obj
        return obj

    def __init__(self, *args, **kwargs):
        pass

    def with_deleted(self):
        return self.__class__(db.class_mapper(self._mapper_zero().class_),
                              session=db.session(), _with_deleted=True)

    def _get(self, *args, **kwargs):
        # this calls the original query.get function from the base class
        return super(QueryWithSoftDelete, self).get(*args, **kwargs)

    def get(self, *args, **kwargs):
        # the query.get method does not like it if there is a filter clause
        # pre-loaded, so we need to implement it using a workaround
        obj = self.with_deleted()._get(*args, **kwargs)
        return obj if obj is not None and not obj.deleted else None


class QueryWithSoftDeleteAndAccess(BaseQuery):
    _with_deleted = False
    _with_access_check = False

    def __new__(cls, *args, **kwargs):
        obj = super(QueryWithSoftDeleteAndAccess, cls).__new__(cls)
        obj._with_deleted = kwargs.pop('_with_deleted', False)
        obj._with_access_check = kwargs.pop('_with_access_check', False)
        if len(args) > 0:
            super(QueryWithSoftDeleteAndAccess, obj).__init__(*args, **kwargs)
            obj = obj.filter_by(
                deleted=False) if not obj._with_deleted else obj
            if request and obj._with_access_check:
                for entity in obj._entities:
                    obj = entity.mapper.class_.access_filter(obj)
            if request and request.args.get('include'):
                join_list = request.args.get('include').split(',')
                options = []
                for join_entry in join_list:
                    options.append(joinedload(join_entry))
                obj = obj.options(options)
        return obj

    def __init__(self, *args, **kwargs):
        pass

    def with_deleted(self):
        return self.__class__(db.class_mapper(self._mapper_zero().class_),
                              session=db.session(), _with_deleted=True)

    def with_access_check(self):
        return self.__class__(db.class_mapper(self._mapper_zero().class_),
                              session=db.session(), _with_access_check=True)

    def raw(self):
        return self.__class__(db.class_mapper(self._mapper_zero().class_),
                              session=db.session(), _with_deleted=True,
                              _with_access_check=False)

    def _get(self, *args, **kwargs):
        # this calls the original query.get function from the base class
        return super(QueryWithSoftDeleteAndAccess, self).get(*args, **kwargs)

    def get(self, *args, **kwargs):
        # the query.get method does not like it if there is a filter clause
        # pre-loaded, so we need to implement it using a workaround
        obj = self.with_deleted()._get(*args, **kwargs)
        return obj if obj is None or self._with_deleted or not \
            obj.deleted else None

    def get_with_deleted(self, *args, **kwargs):
        return self.with_deleted()._get(*args, **kwargs)


class VanillaColumn(_Column):
    def __init__(self, *args, protected=False, mutable=True, private=False,
                 **kwargs):
        super(VanillaColumn, self).__init__(*args, **kwargs)
        self.is_protected = protected
        self.is_mutable = mutable
        self.is_private = private

    def copy(self, *args, **kwargs):
        c = super(VanillaColumn, self).copy(*args, **kwargs)
        c.is_protected = self.is_protected
        c.is_mutable = self.is_mutable
        c.is_private = self.is_private
        return c


class VanillaRelationshipProperty(RelationshipProperty):
    def __init__(self, *args, protected=True, **kwargs):
        super(VanillaRelationshipProperty, self).__init__(*args, **kwargs)
        self.is_protected = protected


db.relationship = VanillaRelationshipProperty

db.Column = VanillaColumn


class MutableValidator(Validator):
    def transform(self, value):
        return value

    # hook over method protection
    def _FlaskValidator__validate(self, target, value, oldvalue, initiator):
        try:
            value = self.transform(value)
        except Exception:
            pass
        return super(MutableValidator, self)._FlaskValidator__validate(
            target, value, oldvalue, initiator)


class Json(TypeDecorator):

    @property
    def python_type(self):
        return object

    impl = types.String

    def process_bind_param(self, value, dialect):
        return json.dumps(value, cls=VanillaJSONEncoder)

    def process_literal_param(self, value, dialect):
        return value

    def process_result_value(self, value, dialect):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return None


class ValidateDate(MutableValidator):
    def transform(self, value):
        if isinstance(value, str):
            return datetime.strptime(value, "%Y-%m-%d")
        else:
            return value

    def check_value(self, value):
        # return isinstance(value, date)
        return True


class ValidateDateTime(MutableValidator):
    def transform(self, value):
        if isinstance(value, str):
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            return value

    def check_value(self, value):
        return isinstance(value, datetime)


def default_tenant(context):
    return context.current_parameters['user'].tenant_id


class VersionMixin:
    version_id = db.Column(Integer, nullable=False)
    __mapper_args__ = {
        "version_id_col": version_id
    }


class BaseModel(object):
    id = db.Column(Integer, primary_key=True, autoincrement=True)
    created_at = db.Column(DateTime, default=datetime.now,
                           onupdate=datetime.now, protected=True)
    updated_at = db.Column(DateTime, default=datetime.now,
                           onupdate=datetime.now, protected=True)
    deleted_at = db.Column(DateTime, protected=True)
    deleted = db.Column(Boolean, default=False, server_default=true(),
                        nullable=False, protected=True)

    query_class = QueryWithSoftDeleteAndAccess

    def soft_delete(self, session):
        """Mark this object as deleted."""
        self.deleted = True
        self.deleted_at = datetime.now()
        session.add(self)

    def populate_from_request(self):
        self.populate(**json.loads(request.data))

    def populate(self, **data):
        data.pop('id', None)  # can be protected but better to exclude it
        if request:
            errors = {}
            saved = inspect(self).persistent
            for key, value in data.items():
                field = self.__table__.columns._data.get(key)
                if field is None or field.is_protected or field.is_private or (
                        saved and not field.is_mutable):
                    continue
                try:
                    setattr(self, key, value)
                except ValueError as e:
                    errors[key] = str(e)
            if errors:
                raise ModelValidationError(errors)
        else:
            for key, value in data.items():
                setattr(self, key, value)

    def as_dict(self):
        self.id  # lazy reload for __dict__, a bit of hack
        return {k: v for k, v in self.__dict__.items() if
                k != '_sa_instance_state'}

    def to_api(self, join_relations=True):
        self.id  # lazy reload for __dict__, a bit of hack
        public_cols = [col.name for col in self.__table__.columns
                       if not col.is_private]
        data = {k: v for k, v in self.as_dict().items() if
                k in public_cols}

        # whether to include relationships, example: include=posts,comments
        if request.args.get('include') and join_relations:
            for relation in request.args.get('include').split(','):
                try:
                    entry = getattr(self, relation)  # for lazy load
                    if isinstance(entry, BaseModel):
                        data[relation] = entry.to_api(
                            join_relations=False) \
                            if not entry.deleted and entry.check_permission(
                            Permission.READ, abort_on_fail=False) else None
                    elif isinstance(entry, list):
                        data[relation] = [i.to_api(join_relations=False) for i
                                          in entry if
                                          not i.deleted and i.check_permission(
                                              Permission.READ,
                                              abort_on_fail=False)]
                except AttributeError:
                    abort(400, f"No such relation: {relation}")
        return data

    @classmethod
    def access_filter(cls, query):
        return query

    @classmethod
    def __declare_last__(cls):
        for col in cls.__table__.columns:
            type = col.type.python_type

            if type == str:
                ValidateString(getattr(cls, col.name), allow_null=col.nullable,
                               throw_exception=True)
                if col.type.length:
                    ValidateLength(
                        getattr(cls, col.name), col.type.length,
                        throw_exception=True,
                        message=f'Max length is { col.type.length}')
            elif type == int:
                ValidateInteger(
                    getattr(cls, col.name),
                    allow_null=col.nullable, throw_exception=True)
            elif type == float:
                ValidateNumeric(
                    getattr(cls, col.name),
                    allow_null=col.nullable, throw_exception=True)
            elif type == date:
                ValidateDate(getattr(cls, col.name), allow_null=col.nullable,
                             throw_exception=True)
            elif type == datetime:
                ValidateDateTime(getattr(cls, col.name),
                                 allow_null=col.nullable, throw_exception=True)

        BaseModel.validators()

    @staticmethod
    def validators():
        """Put here your validators"""
        pass

    def _validate_not_null_columns(self):
        errors = {}
        public_cols = [col for col in self.__table__.columns
                       if not col.is_private]
        for col in public_cols:
            if not col.nullable and \
                    not col.default and \
                    not col.server_default \
                    and not col.autoincrement \
                    and not getattr(self, col.name):
                errors[col.name] = 'Should be specified'
        if errors:
            raise ModelValidationError(errors=errors)

    def validate_on_create(self):
        self._validate_not_null_columns()
        self.validate()

    def validate(self):
        pass

    def _check_permission(self, action):
        return True

    def check_permission(self, action, abort_on_fail=True):
        has_permission = self._check_permission(action)
        if not has_permission and abort_on_fail:
            abort(401)
        return has_permission


class AccessType:
    PRIVATE = 'private'
    PROTECTED = 'protected'
    TENANT_PUBLIC = 'tenant_public'
    PUBLIC = 'public'


class BaseEntity(BaseModel):
    @declared_attr
    def user(cls):
        return db.relationship('User')

    @declared_attr
    def user_id(cls):
        return db.Column(Integer, ForeignKey('user.id'))

    @classmethod
    def access_filter(cls, query):
        query = query.filter(
            (cls.access != AccessType.PRIVATE) | (
                    cls.user_id == g.user.id)
        )
        return query

    def populate_from_request(self):
        super(BaseEntity, self).populate_from_request()
        self.user_id = g.user.id

    def _check_permission(self, action):
        if not g.user:
            return False
        if g.user.has_role(DefaultRoles.SUPER_ADMIN.name):
            return True

        if g.user.id != self.user_id:
            if self.access != AccessType.PUBLIC or action != Permission.READ:
                return False

        return True

    def is_unique(self, field, value):
        _filter = {field: value, 'user_id': g.user.id}
        return not bool(self.__class__.query.filter_by(
            **_filter).count())

    def _verify_relationships(self):
        for name, rel in inspect(self.__class__).relationships.items():
            if not rel.is_protected or rel.direction != MANYTOONE:
                continue

            rel_column = list(rel._calculated_foreign_keys)[0]
            if rel_column.is_protected or rel_column.is_private:
                continue
            rel_class = rel.mapper.class_
            if not issubclass(rel_class, BaseEntity):
                continue
            unverified_id = getattr(self, rel_column.name)
            if not unverified_id:
                continue
            obj = rel_class.query.get(unverified_id)
            if not obj:
                raise ModelValidationError(errors={
                    rel_column:
                        f'{unverified_id} : object with such id not found'
                })
            else:
                obj.check_permission(Permission.WRITE)

    def _verify_relationships_old(self):
        for name, rel in inspect(self.__class__).relationships.items():
            if rel.direction != MANYTOONE:
                continue
            rel_column = list(rel._calculated_foreign_keys)[0]
            if rel_column.is_protected or rel_column.is_private:
                continue
            rel_class = rel.mapper.class_
            if not issubclass(rel_class, BaseEntity):
                continue
            if rel_class not in self.__verify_relationships_list__:
                continue
            unverified_id = getattr(self, rel_column.name)
            if not unverified_id:
                continue
            obj = rel_class.query.get(unverified_id)
            if not obj:
                raise ModelValidationError(errors={
                    rel_column:
                        f'{unverified_id} : object with such id not found'
                })
            else:
                obj.check_permission(Permission.WRITE)

    def validate_on_create(self):
        self._validate_not_null_columns()
        self._verify_relationships()
        self.validate()

    access = db.Column(String, default=AccessType.TENANT_PUBLIC)


class UniqueNameEntity(BaseEntity):
    """Should only extends BaseEntity"""
    __table_args__ = (UniqueConstraint('name', 'user_id',
                                       name='_unique_name_user'),)

    @declared_attr
    def name(cls):
        return db.Column(String, nullable=False)

    @validates('name')
    def validate_name(self, key, name):
        # consider 'self' to be a BaseEntity subclass
        if self.name == name:
            return name
        if not self.is_unique('name', name):
            raise ModelValidationError(errors={'name': 'Already taken'})
        return name


class BaseMultiTenantEntity(BaseEntity):

    @declared_attr
    def tenant_id(cls):
        return db.Column(Integer, ForeignKey('tenant.id'))

    @declared_attr
    def tenant(cls):
        return db.relationship('Tenant')

    def populate_from_request(self):
        super(BaseMultiTenantEntity, self).populate_from_request()
        self.user_id = g.user.id
        self.tenant_id = g.user.tenant_id

    def _check_permission(self, action):
        if not g.user:
            return False
        if g.user.has_role(DefaultRoles.SUPER_ADMIN.name):
            return True
        if g.user.has_role(DefaultRoles.TENANT_ADMIN.name):
            return True
        if not (g.user.has_permission('ALL') or g.user.has_permission(
                action, self.__tablename__)):
            return False
        if g.user.id != self.user_id:
            if self.access == AccessType.PRIVATE:
                return False
            elif self.access == AccessType.PROTECTED and \
                    action != Permission.READ:
                return False

        return True

    def is_unique(self, field, value):
        _filter = {field: value, 'tenant_id': g.user.tenant_id}
        return not bool(self.__class__.query.filter_by(
            **_filter).count())

    @classmethod
    def access_filter(cls, query):
        query = query.filter_by(tenant_id=g.user.tenant_id)
        query = query.filter(
            (cls.access != AccessType.PRIVATE) | (
                    cls.user_id == g.user.id)
        )
        return query


class UniqueNameTenantEntity(BaseMultiTenantEntity):
    """Should only extends BaseMultiTenantEntity"""
    __table_args__ = (UniqueConstraint('name', 'tenant_id',
                                       name='_unique_name_tenant'),)

    @declared_attr
    def name(cls):
        return db.Column(String)

    @validates('name')
    def validate_name(self, key, name):
        # consider 'self' to be a BaseMultiTenantEntity subclass
        if self.name == name:
            return name
        if not self.is_unique('name', name):
            raise ModelValidationError(errors={'name': 'Already taken'})
        return name


user_to_role = db.Table(
    'user_to_role', db.Model.metadata,
    db.Column('user_id', Integer, ForeignKey('user.id')),
    db.Column('role_name', String, ForeignKey('role.name'))
)


class UserBase(BaseModel):
    @declared_attr
    def roles(cls):
        return db.relationship('Role', secondary=user_to_role, lazy='joined')

    def has_role(self, role):
        name = role if isinstance(role, str) else role.name
        return name in [r.name for r in self.roles]

    def has_permission(self, action, model=None):
        return bool(action in self.permissions.get(model, []))

    @property
    def permissions(self):
        permissions = {}
        for role in self.roles:
            for p in role.permissions:
                if not permissions.get(p.model):
                    permissions[p.model] = set(p.type)
                else:
                    permissions[p.model].add(p.type)
        return permissions

    def to_api(self, join_relations=True):
        data = super(UserBase, self).to_api(join_relations=join_relations)
        data['roles'] = [r.name for r in self.roles]
        return data


class TenantUser(UserBase):
    @declared_attr
    def tenant_id(cls):
        return db.Column(Integer, ForeignKey('tenant.id'))

    @declared_attr
    def tenant(cls):
        return db.relationship('Tenant')


class Role(BaseModel, db.Model):
    name = db.Column(String(length=50), primary_key=True)
    description = db.Column(db.Text())
    permissions = db.relationship('Permission')

    def id(self):
        # for compatibility
        return self.name

    def to_api(self, join_relations=True):
        data = super(Role, self).to_api(join_relations=join_relations)
        data['permissions'] = [p.to_api() for p in self.permissions]

    def populate_from_request(self):
        super(Role, self).populate_from_request()
        for permission_id in request.json['permissions']:
            permission = Permission.query.get(permission_id)
            if permission:
                Role.permissions.append(permission)


class Permission(BaseModel, db.Model):
    # Default permissions
    READ = 'READ'
    WRITE = 'WRITE'
    HARD_WRITE = 'HARD WRITE'
    READ_DELETED = 'READ_DELETED'
    SUPER_ADMIN = 'SUPER_ADMIN'

    id = db.Column(Integer, primary_key=True, autoincrement=True)
    type = db.Column(String)
    model = db.Column(String, default='ALL')
    role_name = db.Column(Integer, ForeignKey('role.name'))
    role = db.relationship('Role')

    def __eq__(self, other):
        return self.type == other.type and self.model == other.model

    def __hash__(self):
        return hash(self.type + (self.model or ""))


class DefaultRoles:
    SUPER_ADMIN = Role(name='super-admin', permissions=[
        Permission(type=Permission.READ),
        Permission(type=Permission.WRITE),
        Permission(type=Permission.HARD_WRITE),
        Permission(type=Permission.SUPER_ADMIN),
        Permission(type=Permission.READ_DELETED)])
    TENANT_ADMIN = Role(name='tenant-admin', permissions=[
        Permission(type=Permission.READ),
        Permission(type=Permission.WRITE),
        Permission(type=Permission.HARD_WRITE)])
    USER = Role(name='user', permissions=[
        Permission(type=Permission.READ),
        Permission(type=Permission.WRITE)])
    GUEST = Role(name='guest', permissions=[
        Permission(type=Permission.READ)])

    ALL = [SUPER_ADMIN, TENANT_ADMIN, USER, GUEST]


class TenantBase(BaseModel):
    @declared_attr
    def users(cls):
        return db.relationship('User')


def route(path, **options):
    """Works only for class (extends BaseAPI) methods"""

    def decorator(f):
        f.route = (path, options)
        return f

    return decorator


class BaseAPI:
    def register(self, api, prefix):
        method_list = [getattr(self.__class__, func) for func in
                       dir(self.__class__) if
                       callable(getattr(self.__class__, func))]

        for f in method_list:
            if hasattr(f, 'route'):
                path, options = f.route
                if not path.startswith('/'):
                    path = '/' + path
                api.add_url_rule(
                    f'/{prefix}{path}', f'{f.__name__}', f, **options
                )


class ModelAPI(BaseAPI):
    class Methods:
        GET = 1
        CREATE = 2
        UPDATE = 3
        DELETE = 4
        GET_LIST = 5
        DELETE_LIST = 6
        SOFT_DELETE = 7
        GET_DELETED = 8
        DEFAULT_ALL = [CREATE, UPDATE, SOFT_DELETE, GET, GET_LIST, DELETE_LIST,
                       DELETE]

    def check_permission(self, obj, action):
        obj.check_permission(action)

    def __init__(self, model_class, db=None, app=None, methods=(),
                 max_results=100, name=None, prefix=''):
        self.model = model_class
        self.name = name or self.model.__tablename__
        self.full_prefix = prefix + self.name
        self.max_results = max_results
        self.fields = [
            prop.key for prop in
            class_mapper(self.model).iterate_properties
            if isinstance(prop, ColumnProperty)
        ]
        self.methods = methods or ModelAPI.Methods.DEFAULT_ALL

        if app:
            self.app = app
            self.init_app(app)
            self.db = app.db
        else:
            self.db = db

    def init_app(self, app):
        self.register(app)

    def get(self, id):
        obj = self.model.query.get_or_404(id)
        self.check_permission(obj, Permission.READ)
        return jsonify(obj.to_api())

    def query_access_filter(self, query):
        """override this to add custom query filter"""
        return query

    def get_list(self):
        filters = request.args
        page = filters.get('page', type=int)
        per_page = filters.get('limit', type=int)
        sort_by = filters.get('sort_by')
        decs = filters.get('decs', default=False, type=bool)
        with_deleted = request.args.get('with-deleted', type=bool,
                                        default=False)
        query = self.model.query.with_access_check()

        if with_deleted and g.user.has_permission(Permission.READ_DELETED,
                                                  self.model):
            query = query.with_deleted()

        for name, value in filters.items():
            if name.endswith('-min'):
                field_name = name.split('-min')[0]
                if field_name in self.fields:
                    query = query.filter(
                        getattr(self.model, field_name) >= value)
            elif name.endswith('-max'):
                field_name = name.split('-max')[0]
                if field_name in self.fields:
                    query = query.filter(
                        getattr(self.model, field_name) <= value)
            elif name.endswith('-like'):
                field_name = name.split('-like')[0]
                if field_name in self.fields:
                    query = query.filter(
                        getattr(self.model, field_name).like(value))
            else:
                if name in self.fields:
                    query = query.filter(getattr(self.model, name) == value)

        query = self.query_access_filter(query)

        if sort_by:
            query = query.order_by(sort_by + ' desc' if decs else '')

        if page:
            query = query.paginate(page=page, per_page=per_page)
            return jsonify(
                {'items': [obj.to_api() for obj in query.items],
                 'pages': query.pages})

        return jsonify(
            [obj.to_api() for obj in query.limit(self.max_results).all()])

    def delete(self, id):
        obj = self.model.query.get_or_404(id)
        self.check_permission(obj, Permission.WRITE)
        obj.soft_delete(self.db.session)
        self.db.session.commit()
        self.app.log_user_action(obj, 'deleted')
        return 'DELETED'

    def hard_delete(self, id):
        obj = db.session.query(self.model).get(id)
        if not obj:
            abort(404)
        self.check_permission(obj, Permission.HARD_WRITE)
        db.session.delete(obj)
        self.db.session.commit()
        self.app.log_user_action(obj, 'deleted')
        return 'DELETED'

    def delete_all(self):
        deleted = []
        for obj_id in request.json.get('id_list', []):
            try:
                obj = db.session.query(self.model).get(id)
                if not obj:
                    continue
                self.check_permission(obj, Permission.HARD_WRITE)
                db.session.delete(obj)
                db.session.commit()
                deleted.append(obj_id)
            except Exception as e:
                self.app.logger.exeption(f'Failed to delete obj, id: {obj_id}')
        return json.dumps(deleted)

    def restore(self, id):
        obj = self.model.query.get_with_deleted(id)
        if not obj:
            abort(404)
        self.check_permission(obj, Permission.HARD_WRITE)
        self.pre_restore(obj)
        obj.deleted = False
        self.db.session.add(obj)
        self.db.session.commit()
        self.post_restore(obj)
        self.app.log_user_action(obj, 'restored')
        return jsonify(obj.to_api())

    def create(self):
        f"""HER{self.model}"""
        obj = self.model()
        obj.populate_from_request()
        self.check_permission(obj, Permission.WRITE)
        self.pre_create(obj)
        obj.validate_on_create()  # needed only for create
        self.db.session.add(obj)
        self.db.session.commit()
        self.post_create(obj)
        self.app.log_user_action(obj, 'created')
        return jsonify(obj.to_api())

    def update(self, id):
        obj = self.model.query.get_or_404(id)
        self.check_permission(obj, Permission.WRITE)
        self.pre_update(obj)
        obj.populate_from_request()
        obj.validate()
        self.db.session.add(obj)
        self.db.session.commit()
        self.post_update(obj)
        self.app.log_user_action(obj, 'updated')
        return jsonify(obj.to_api())

    def pre_create(self, obj):
        pass

    def post_create(self, obj):
        pass

    def pre_update(self, obj):
        pass

    def post_update(self, obj):
        pass

    def pre_delete(self, obj, hard=False):
        pass

    def post_delete(self, obj, hard=False):
        pass

    def pre_delete_all(self, ids):
        pass

    def post_delete_all(self, ids):
        pass

    def pre_restore(self, obj):
        pass

    def post_restore(self, obj):
        pass

    def check_if_is_unique(self, field, value):
        # value is a string, so it should be converted first
        col_type = getattr(self, field).type.python_type
        try:
            value = col_type(value)
        except ValueError:
            return 'Invalid value', 400
        return jsonify({'result': self.model.is_unique(field, value)})

    def register(self, api):
        super(ModelAPI, self).register(api, self.full_prefix)
        if ModelAPI.Methods.GET in self.methods:
            api.add_url_rule(
                f'/{self.full_prefix}/<int:id>', f'get_{self.name}',
                self.get, methods=['GET']
            )
        if ModelAPI.Methods.GET_LIST in self.methods:
            api.add_url_rule(
                f'/{self.full_prefix}/', f'get_{self.name}_list',
                self.get_list, methods=['GET']
            )
        if ModelAPI.Methods.SOFT_DELETE in self.methods:
            api.add_url_rule(
                f'/{self.full_prefix}/<int:id>', f'delete_{self.name}',
                self.delete, methods=['DELETE']
            )
        if ModelAPI.Methods.DELETE in self.methods:
            api.add_url_rule(
                f'/{self.full_prefix}/<int:id>/hard-delete',
                f'hard_delete_{self.name}',
                self.hard_delete, methods=['DELETE']
            )
        if ModelAPI.Methods.DELETE in self.methods:
            api.add_url_rule(
                f'/{self.full_prefix}/<int:id>/delete-all',
                f'delete_all_{self.name}',
                self.delete_all, methods=['DELETE']
            )
        if ModelAPI.Methods.SOFT_DELETE in self.methods:
            api.add_url_rule(
                f'/{self.full_prefix}/<int:id>/restore',
                f'restore_{self.name}',
                self.restore, methods=['POST']
            )
        if ModelAPI.Methods.CREATE in self.methods:
            api.add_url_rule(
                f'/{self.full_prefix}', f'create_{self.name}',
                self.create, methods=['POST']
            )
        if ModelAPI.Methods.UPDATE in self.methods:
            api.add_url_rule(
                f'/{self.full_prefix}/<int:id>', f'update_{self.name}',
                self.update, methods=['PUT']
            )
        api.add_url_rule(
            f'/{self.full_prefix}/<field>/is-unique/<value>',
            f'check_unique_{self.name}',
            self.check_if_is_unique, methods=['GET']
        )


class TenantAdminAPI(ModelAPI):
    def query_access_filter(self, query):
        return query.filter_by(tenant_id=g.user.tenant_id)

    def check_permission(self, obj=None, action=None):
        return g.user.has_role('tenant-admin')

    @route('/add-role/<int:user_id>/<role_name>', methods=['post'])
    def add_role(self, user_id, role_name):
        self.check_permission()
        user = self.app.User.query.get_or_404(user_id)
        role = Role.query.get_or_404(role_name)
        user.roles.append(role)
        self.db.session.add(user)
        self.db.session.commit()
        self.app.log_user_action(user, f'role added: {role_name}')

    @route('/remove-role/<int:user_id>/<role_name>', methods=['post'])
    def remove_role(self, user_id, role_name):
        self.check_permission()
        user = self.app.User.query.get_or_404(user_id)
        try:
            role = [r for r in user.roles if r.name == role_name][0]
        except KeyError:
            return
        user.roles.remove(role)
        self.db.session.add(user)
        self.db.session.commit()
        self.app.log_user_action(user, f'role removed: {role_name}')

    def register(self, api):
        super(TenantAdminAPI, self).register(api)


class SuperAdminAPI(ModelAPI):

    def query_access_filter(self, query):
        return query

    def check_permission(self, obj, action):
        return g.user.has_role('super-admin')


class RoleAPI(SuperAdminAPI):
    def __init__(self, db=None, app=None, methods=(),
                 max_results=100, name=None):
        super(RoleAPI, self).__init__(Role, app, max_results=max_results)


class PermissionsAPI(SuperAdminAPI):
    def __init__(self, db=None, app=None, methods=(),
                 max_results=100, name=None):
        super(PermissionsAPI, self).__init__(Permission, app,
                                             max_results=max_results)


def _get_entities():
    return [model for model in db.Model._decl_class_registry.values()
            if isinstance(model, type) and issubclass(model, BaseEntity)]


def init_error_handlers(app):
    @app.errorhandler(ModelValidationError)
    def model_validation(e):
        return json.dumps({'errors': e.errors}), 422

    @app.errorhandler(IntegrityError)
    def orm_fail(e):
        return f'Invalid entity', 422

    @app.errorhandler(ValueError)
    def model_modification_validation(e):
        return json.dumps({'error': str(e)}), 400


def init_user_modifications_tracking(app):
    class UserAction(app.db.Model):
        id = db.Column(db.Integer, primary_key=True, autoincrement=True)
        name = db.Column(db.String)
        datetime = db.Column(db.DateTime, default=datetime.now)
        message = db.Column(db.Text)
        entity = db.Column(db.String)
        user_id = db.Column(db.Integer)

    @app.user_action_handler
    def add_action(obj, action, message=None):
        app.db.session.add(
            UserAction(name=action, message=message, entity=obj.__tablename__,
                       user_id=g.user.id))
        app.db.session.commit()


def _init__default_logging_config(app):
    dictConfig({
        "version": 1,
        "disable_existing_loggers": 0,
        "root": {
            "level": "DEBUG",
            "handlers": [
                "console",
                "file",
            ]
        },
        "loggers": {

        },
        "formatters": {
            "precise": {
                "format": "%(asctime)s %(name)-15s %(levelname)-8s %(message)s"
            },
        },
        "handlers": {
            "console": {
                "formatter": "precise",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "level": "DEBUG"
            },
            "file": {
                "formatter": "precise",
                "backupCount": 3,
                "level": "WARNING",
                "maxBytes": 10240000,
                "class": "logging.handlers.RotatingFileHandler",
                "filename": f"{app.name}.log"
            }
        }
    })


class UserMode:
    SIMPLE = 1
    MULTI_TENANT = 2


class VanillaJSONEncoder(JSONEncoder):
    def default(self, o):
        if isinstance(o, (date, datetime)):
            return o.isoformat()

        return super().default(o)


class FlaskVanilla(Flask):
    json_encoder = VanillaJSONEncoder

    def __init__(self, import_name, user_extension=None, tenant_extension=None,
                 user_action_tracking=True, user_mode=UserMode.SIMPLE,
                 default_logging=False, **kwargs):

        super(FlaskVanilla, self).__init__(
            import_name=import_name,
            **kwargs
        )

        self._default_configs(logging=default_logging)
        db.init_app(self)
        self.db = db
        self.models = []
        self.user_mode = user_mode

        class EmptyExtension:
            pass

        user_extension = user_extension or EmptyExtension
        tenant_extension = tenant_extension or EmptyExtension

        if user_mode == UserMode.MULTI_TENANT:
            class User(user_extension, TenantUser, db.Model):
                pass

            class Tenant(tenant_extension, TenantBase, db.Model):
                pass

            self.Tenant = Tenant
            self.User = User
            SuperAdminAPI(Tenant, app=self)
            TenantAdminAPI(User, app=self)

        else:
            class User(user_extension, UserBase, db.Model):
                pass

            self.User = User
            SuperAdminAPI(User, app=self)

        self.init_api()

        init_error_handlers(self)

        self.user_action_handlers = []

        if user_action_tracking:
            self.init_user_modifications_tracking()

    def add_model_rest_api(self, model):
        ModelAPI(model, self.db).register(self)

    def init_api(self):
        global MODELS
        for model in MODELS:
            ModelAPI(model, db, self)
            self.models.append(model)

    def log_user_action(self, obj, action):
        self.logger.info(f'{obj.__tablename__} {action}. User ID: {g.user.id}')
        for f in self.user_action_handlers:
            f(obj, action)

    def user_action_handler(self, f):
        self.user_action_handlers.append(f)

    def init_user_modifications_tracking(self):
        init_user_modifications_tracking(self)

    def entity_event(self, model, action):
        def wrapper(f):
            def handler(obj, _action):
                if obj.__tablename__ == model.__tablename__ \
                        and action == _action:
                    f(obj, _action)

            self.user_action_handlers.append(handler)

        return wrapper

    def _default_configs(self, logging=False):
        self.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{self.name}.db'
        self.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
        self.config['CACHE_TYPE'] = 'simple'
        if logging:
            _init__default_logging_config(self)


MODELS = []


def setup_cli(app):
    @app.cli.command()
    def init_default_data():
        with current_app.app_context():
            for role in DefaultRoles.ALL:
                if not Role.query.get(role.name):
                    app.db.session.add(role)
            app.db.session.commit()


def generate_api(model_class):
    global MODELS
    MODELS.append(model_class)
    return model_class


class BaseCRUDTestCase:
    app = None
    model_api = None

    @property
    def prefix(self):
        return self.model_api.full_prefix

    def create_fixtures(self):
        pass

    def get_create_obj_fixture(self):
        return {}

    def get_update_obj_fixture(self):
        return {}

    def test_basic_crud(self):
        obj = self.get_create_obj_fixture()
        resp = self.app.test_client().post(f'/{self.prefix}',
                                         data=json.dumps(obj))

        self.assertEqual(200, resp.status_code, 'create fail')
        created = json.loads(resp.data)
        for k, v in obj.items():
            self.assertEqual(v, created.get(k), 'created is not valid')

        resp = self.app.test_client().get(f'/{self.prefix}/{created["id"]}')
        self.assertEqual(200, resp.status_code, 'get by id fail')
        retrieved = json.loads(resp.data)
        self.assertDictEqual(created, retrieved, 'retrieved is not valid')

        update_obj = self.get_update_obj_fixture()

        resp = self.app.test_client().put(f'/{self.prefix}/{created["id"]}',
                                         data=json.dumps(update_obj))

        self.assertEqual(200, resp.status_code, 'update fail')
        retrieved = json.loads(resp.data)
        for k, v in update_obj.items():
            self.assertEqual(v, retrieved.get(k), 'updated is not valid')

        resp = self.app.test_client().delete(f'/{self.prefix}/{created["id"]}')

        self.assertEqual(200, resp.status_code, 'delete fail')

        resp = self.app.test_client().get(f'/{self.prefix}/{created["id"]}')

        self.assertEqual(404, resp.status_code, 'delete fail')

    def test_hard_delete(self):
        obj = self.get_create_obj_fixture()
        resp = self.app.test_client().post(f'/{self.prefix}',
                                         data=json.dumps(obj))

        self.assertEqual(200, resp.status_code, 'create fail')
        created = json.loads(resp.data)

        resp = self.app.test_client().delete(
            f'/{self.prefix}/{created["id"]}/hard-delete')

        self.assertEqual(200, resp.status_code, 'hard delete fail')

        with self.app.app_context():
            obj = self.model_api.model.query.get_with_deleted(created['id'])

        self.assertIsNone(obj)

    def get_list(self):
        for i in range(10):
            obj = self.model_api.model()
            obj.populate(self.get_create_obj_fixture())
            self.model_api.db.session.add(obj)
        self.model_api.db.session.commit()

        resp = self.app.test_client().get(f'/{self.prefix}/')

        self.assertEqual(200, resp.status_code)
        result = json.loads(resp.data)
        self.assertEqual(10, len(result))

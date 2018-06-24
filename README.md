## Flask-Vanilla

This is a small util library for simple flask projects for easy creating
of CRUD api.

It is tented to give you an in-dox solution for typical **enterprise** CRUD.

### SQLAlhemy hacks:
- Column - is replaced with extend class, it provides additional flags:
    `private`, `protected`, `mutable`.
```
some_column = db.Column(db.Integer, private=True)
```
- Relationship - has additional attribute `protected`, it is used to specify,
that when user creates and object, that relates to another,
 foreign key will be verified.
- Json - is a fake Json type, instead of db.JSON - it is using text
on the db side, and performs implicit conversion. Useful for sqlite.
### Mixins

- BaseModel
 Provides feature: soft-delete, populate from dict, populate from request,
 to api dict.
- BaseEntity
 Extends BaseModel, it is "an user object", witch mean it has `user_id`,
 and method `check_permission(str:permission)`.
- VersionMixin - adds version counter.

### Example:

```python
from flask_vanilla import FlaskVanilla, ModelAPI, BaseEntiry, db
from flask_validator import *

class UserExtension:
    email = db.Column(db.String, unique=True)

class ExampleModel(BaseEntiry, db.Model):
    number1 = db.Column(db.Integer, protected=True)

    @staticmethod
    def validators():
        ValidateLessThan(ExampleModel.number1, 100)

app = FlaskVanilla(__name__,
    user_extension=UserExtension,
    user_mode=UserMode.MULTI_TENANT
)

ModelAPI(ExampleModel, app=app)
```

### Generated API:
```
Get one - GET: /example_model/<id>
Get all - GET: /example_model?page={}&limit={}&number1={}&with-deleted=<true/false>...
Create - POST: /example_model/
Update - PUT: /example_model/<id>
Soft delete - DELTE : /example_model/<id>
Hard delete - DELETE: /example_model/hard-delete/<id>
Restore - POST: /example_model/restore/<id>
Delete all - DELETE: /example_model/delete-all (data: {'id_list':[1,2,3...]})
```
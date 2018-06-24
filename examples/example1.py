from flask_vanilla import FlaskVanilla, db, BaseEntity, Json, ModelAPI, \
    UniqueNameEntity, DefaultRoles, BaseCRUDTestCase
from flask import g
from sqlalchemy.ext.declarative import declared_attr


class UserExtension():
    name = db.Column(db.String, unique=True)
    surname = db.Column(db.String)

    @declared_attr
    def posts(self):
        return db.relationship('Post', protected=True)


class Post(BaseEntity, db.Model):
    some_text = db.Column(db.String)
    json_columns = db.Column(Json)


class Comment(BaseEntity, db.Model):
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    post = db.relationship('Post', protected=False)
    text = db.Column(db.Text, nullable=False)


# should have unique name for user
class UniqueNameModel(UniqueNameEntity, db.Model):
    # private col - will not be exposed to api
    number1 = db.Column(db.Integer, private=True)
    # protected col - cannot be set by user
    number2 = db.Column(db.Integer, protected=True)
    # mutable col - cannot be updated after was initialized
    number3 = db.Column(db.Integer, mutable=False)


app = FlaskVanilla(__name__, user_extension=UserExtension)

post_api = ModelAPI(Post, app=app)
comment_api = ModelAPI(Comment, app=app)
unique_name_model_api = ModelAPI(UniqueNameModel, app=app)


@app.before_request
def get_user():
    g.user = app.User(id=1, name='Test',
                      roles=[DefaultRoles.SUPER_ADMIN,
                             DefaultRoles.TENANT_ADMIN])


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run()

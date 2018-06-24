import unittest
from flask_vanilla import BaseCRUDTestCase
from examples.example1 import app, post_api

class PostTestCase(unittest.TestCase, BaseCRUDTestCase):
    model_api = post_api
    app = app

    def setUp(self):
        super(PostTestCase, self).setUp()

    def create_fixtures(self):
        pass

    def get_create_obj_fixture(self):
        return {'some_text': 'blabla', 'json_columns': [1, 2, 3]}

    def get_update_obj_fixture(self):
        return {'some_text': 'blabla2', 'json_columns': [1, 2, 4]}

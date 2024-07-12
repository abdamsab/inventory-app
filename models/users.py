from marshmallow import Schema, fields, validate, ValidationError

class UserSchema(Schema):
    userId = fields.String(required=True)
    firstName = fields.String(required=True, validate=validate.Length(min=1))
    lastName = fields.String(required=True, validate=validate.Length(min=1))
    email = fields.Email(required=True)
    password = fields.String(required=True, load_only=True, validate=validate.Length(min=6))
    role = fields.String(required=True, validate=validate.OneOf(["user", "admin", "powerUser"]))

    class Meta:
        fields = ("userId", "firstName", "lastName", "email", "password", "role")

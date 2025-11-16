from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from getpass import getpass

User = get_user_model()

class Command(BaseCommand):
    help = 'Create a superuser with email as the primary identifier'

    def add_arguments(self, parser):
        parser.add_argument('--email', help='Email address for the superuser')
        parser.add_argument('--password', help='Password for the superuser')
        parser.add_argument('--username', help='Optional username for the superuser')
        parser.add_argument('--first_name', help='First name for the superuser')
        parser.add_argument('--last_name', help='Last name for the superuser')

    def handle(self, *args, **options):
        # Interactive fallback if not provided via CLI
        email = options['email'] or input('Email: ').strip()
        while not email:
            email = input('Email (required): ').strip()

        password = options['password'] or getpass('Password: ')
        while not password:
            password = getpass('Password (required): ')

        username = options.get('username') or input('Username (optional): ').strip()
        first_name = options.get('first_name') or input('First name (optional): ').strip()
        last_name = options.get('last_name') or input('Last name (optional): ').strip()

        try:
            user_data = {
                'email': email,
                'password': password,
                'is_staff': True,
                'is_superuser': True,
                'is_email_verified': True,
                'first_name': first_name,
                'last_name': last_name,
            }

            if username:
                user_data['username'] = username

            user = User.objects.create_user(**user_data)
            user.is_superuser = True
            user.is_staff = True
            user.save()

            self.stdout.write(self.style.SUCCESS(f'Superuser {email} created successfully!'))

        except IntegrityError as e:
            self.stderr.write(f'IntegrityError: {e}')
        except Exception as e:
            self.stderr.write(f'Unexpected error: {e}')

from django.core.management.base import BaseCommand
from django.utils import timezone
from django.conf import settings
from accounts.models import User
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    """
    Permanently delete user accounts that were scheduled for deletion 
    and the grace period (30 days) has expired.
    """
    help = 'Permanently delete accounts that were soft-deleted over 30 days ago'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show which accounts would be deleted without actually deleting them',
        )
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days after which to permanently delete accounts (default: 30)',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed information about each account being processed',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        days_threshold = options['days']
        verbose = options['verbose']
        
        # Calculate the cutoff date
        cutoff_date = timezone.now() - timezone.timedelta(days=days_threshold)
        
        # Find accounts scheduled for deletion before the cutoff date
        accounts_to_delete = User.objects.filter(
            is_active=False,
            scheduled_deletion__isnull=False,
            scheduled_deletion__lte=cutoff_date
        )
        
        account_count = accounts_to_delete.count()
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f'DRY RUN: Would permanently delete {account_count} account(s) '
                    f'that were scheduled for deletion before {cutoff_date.strftime("%Y-%m-%d %H:%M:%S")}'
                )
            )
            
            if account_count > 0 and verbose:
                self.stdout.write('\nAccounts that would be deleted:')
                for account in accounts_to_delete:
                    self.stdout.write(
                        f'  - {account.email} (scheduled for deletion on {account.scheduled_deletion})'
                    )
            
            return
        
        if account_count == 0:
            self.stdout.write(
                self.style.SUCCESS(
                    f'No accounts found for permanent deletion (cutoff: {cutoff_date.strftime("%Y-%m-%d %H:%M:%S")})'
                )
            )
            return
        
        self.stdout.write(
            self.style.WARNING(
                f'Found {account_count} account(s) scheduled for permanent deletion '
                f'(before {cutoff_date.strftime("%Y-%m-%d %H:%M:%S")})'
            )
        )
        
        if verbose:
            self.stdout.write('\nAccounts to be permanently deleted:')
            for account in accounts_to_delete:
                self.stdout.write(
                    f'  - {account.email} (scheduled for deletion on {account.scheduled_deletion})'
                )
        
        # Ask for confirmation if not running in a non-interactive environment
        if not options.get('interactive', True):
            confirmed = True
        else:
            confirmed = input(
                '\nAre you sure you want to permanently delete these accounts? '
                'This action cannot be undone. [y/N]: '
            ).lower().strip() in ('y', 'yes')
        
        if not confirmed:
            self.stdout.write(self.style.WARNING('Operation cancelled.'))
            return
        
        deleted_count = 0
        errors = []
        
        for account in accounts_to_delete:
            try:
                email = account.email
                scheduled_date = account.scheduled_deletion
                
                # Log the deletion for audit purposes
                logger.info(
                    f'Permanently deleting account: {email} '
                    f'(scheduled for deletion on {scheduled_date})'
                )
                
                # Permanently delete the account and all related data
                # This will cascade delete UserProfile, UserPreferences, MagicLinkTokens, etc.
                account.delete()
                
                deleted_count += 1
                
                if verbose:
                    self.stdout.write(
                        self.style.SUCCESS(f'  ✓ Deleted: {email}')
                    )
                
            except Exception as e:
                error_msg = f'Failed to delete account {account.email}: {str(e)}'
                logger.error(error_msg)
                errors.append(error_msg)
                
                if verbose:
                    self.stdout.write(
                        self.style.ERROR(f'  ✗ Failed: {account.email} - {str(e)}')
                    )
        
        # Summary
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS(
            f'PERMANENT DELETION COMPLETED: {deleted_count}/{account_count} accounts deleted'
        ))
        
        if errors:
            self.stdout.write(self.style.ERROR(
                f'ERRORS: {len(errors)} account(s) could not be deleted'
            ))
            for error in errors:
                self.stdout.write(self.style.ERROR(f'  - {error}'))
        
        # Log summary
        logger.info(
            f'Account cleanup completed: {deleted_count} accounts permanently deleted, '
            f'{len(errors)} errors'
        )
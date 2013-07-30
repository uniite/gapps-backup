import email, email.parser, email.utils, errno, gzip, imaplib, hashlib, logging, os, platform, sys
from cStringIO import StringIO

# Monkey-patch for Mac OS X
if platform.system() == "Darwin":
    def getresuid():
        return (os.getgid(), os.getegid(), os.getgid())
    os.getresuid = getresuid
import gnupg

from boto.s3.connection import S3Connection



class MessageArchiver(object):
    def __init__(self):
        self.gpg = gnupg.GPG(use_agent=False)
        self.gpg_fingerprint = GPG_FINGERPRINT
        # Download our GPG key if we don't have it
        try:
            self._lookup_key()
        except StopIteration:
            print "Could not find GPG key. Downloading from keyserver."
            self.gpg.recv_keys("keys.gnupg.net", "DF900EB0B6458585")
            self._lookup_key()
        # Setup storage providers
        self.providers = {}
        for name, config in STORAGE_PROVIDERS.iteritems():
            # Connect to the storage provider
            connection = S3Connection(config["key"], config["secret"])
            self.providers[name] = {"connection": connection}
            bucket = connection.get_bucket(config["bucket"])
            self.providers[name]["bucket"] = bucket
            # List the container's contents
            print "Retrieving list of objects from storage provider..."
            self.providers[name]["objects"] = [k.name for k in bucket.list()]

    def _lookup_key(self):
        self.gpg_fingerprint = next(k["fingerprint"] for k in self.gpg.list_keys() if k["keyid"] == GPG_KEY_ID)

    def encrypt(self, data):
        return str(self.gpg.encrypt(data, self.gpg_fingerprint))

    def archive(self, raw_message, path):
        f = gzip.open(path, "wb")
        f.write(self.encrypt(raw_message))
        f.close()

    def archive_to_cloud(self, raw_message, path):
        stream = StringIO()
        f = gzip.GzipFile(fileobj=stream, mode="wb")
        f.write(self.encrypt(raw_message))
        f.close()
        hash = hashlib.md5(stream.getvalue()).hexdigest()
        for provider, config in self.providers.iteritems():
            key = config["bucket"].new_key(path)
            key.set_metadata("Content-Type", "applcation/gzip")
            key.set_metadata("archive-hash", hash)
            key.set_contents_from_string(stream.getvalue())

    def exists(self, path):
        exists = 0
        for provider, config in self.providers.iteritems():
            if path in config["objects"]:
                exists += 1
        return exists == len(self.providers)


archiver = MessageArchiver()

# TODO: Restore with something like:
# mail.append("[Gmail]/All Mail", "", imaplib.Time2Internaldate(timestamp), raw_message)



# http://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc: # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise

def get_message(uid):
    typ, data = mail.uid("FETCH", uid, '(RFC822)')
    if typ != "OK":
        raise Exception("Could not fetch message with uid %s" % repr(uid))
    return data

class MessageBackup(object):

    def __init__(self, headers, raw_message):
        self.headers = headers
        self.message = raw_message
        self.date = email.utils.parsedate(self.headers["Date"])
        self.path = self.__class__.message_path(self.headers["Message-ID"])

    def save(self):
        #mkdir_p(os.path.dirname(self.path))
        #archived_message = archiver.archive(self.message, self.path)
        archived_message = archiver.archive_to_cloud(self.message, self.path)

    @classmethod
    def message_path(cls, id):
        id_hash = hashlib.sha1(id).hexdigest()
        return "%s/%s/%s/%s.rfc822.gpg.gz" % (BACKUP_PATH, id_hash[:3], id_hash[3:6], id_hash)

    @classmethod
    def exists(cls, msg_id):
        #return os.path.exists(cls.message_path(msg_id))
        return archiver.exists(cls.message_path(msg_id))



def bulk_fetch(uids, fields, chunk_size=100, raw_message=False):
    """
    Fetches a bunch of messages and makes them available as a generator.
    """
    parser = email.parser.Parser()
    for uid_chunk, pos in chunker(uids, chunk_size):
        print "Fetching chunk %s" % pos
        type, data = mail.uid("fetch", ",".join(uid_chunk), fields)
        if typ != "OK": raise Exception("Failed to retrieve messsages")
        # Check each message in this batch
        for msg in data:
            # Parse out the UID as well
            if not "(UID " in msg[0]:
                continue
            uid = msg[0].split(" ", 4)[2]
            # Parse the message and pass it back
            # If raw_message=True, only parse the headers, and return the entire message separately
            if raw_message:
                yield uid, parser.parsestr(msg[1], True), msg[1]
            else:
                yield uid, parser.parsestr(msg[1])

# http://stackoverflow.com/questions/434287/what-is-the-most-pythonic-way-to-iterate-over-a-list-in-chunks
def chunker(seq, size):
    return ((seq[pos:pos + size], pos) for pos in xrange(0, len(seq), size))

mail = imaplib.IMAP4_SSL("imap.gmail.com")
mail.login("jon@jbotelho.com", "iqlcysbgmtheornh")
try:
    typ, data = mail.select("[Gmail]/All Mail")
    if typ != "OK":
        raise Exception("Could not find Gmail's 'All Mail' folder")
    try:
        # Get a list of all our messages (just their UIDs)
        typ, data = mail.uid("search", ("ALL"))
        uids = data[0].split(" ")
        uids_to_backup = []
        print "Found {:,} messages".format(len(uids))
        # Download all their Message IDs (100 at a time), so we can compare to our existing backup
        # Fetch just the Message-ID header
        for uid, msg in bulk_fetch(uids[:100], "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])", chunk_size=1000):
            if not MessageBackup.exists(msg["Message-ID"]):
                # Yes (no existing backup found)
                uids_to_backup.append(uid)

        # Run the backup
        print "Need to backup {:,} messages".format(len(uids_to_backup))
        # Download the entire messages as RFC822 in batches (standard E-Mail format)
        archive_jobs = []
        for uid, headers, raw_msg in bulk_fetch(uids_to_backup, "(RFC822)", raw_message=True    ):
            backup = MessageBackup(headers, raw_msg)
            print "Backing up %s to %s" % (msg["Message-ID"], backup.path)
            backup.save()

    finally:
        mail.close()
finally:
    mail.logout()
#!/usr/bin/env python3.7

import os
import sys
import logging
import re
import time
from datetime import datetime
import praw
import prawcore.exceptions
import yaml


# setup
os.environ['TZ'] = 'UTC'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(funcName)s | %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
try:
    assert praw.__version__.startswith('7.3.')
    configuration = sys.argv[1]
    r = praw.Reddit(configuration)
    r.validate_on_submit = True
    ME = str(r.user.me())
    HOME = r.subreddit(ME)
    SCAN = r.subreddit(r.config.custom.get("scan", "all"))
except IndexError:
    logging.error("usage: {} <praw.ini section>".format(sys.argv[0]))
    sys.exit(1)
except Exception as e:
    logging.error("failed to obtain PRAW instance: {}".format(e))
    time.sleep(60)
    sys.exit(1)


# global data
STATUS_POST = None
FRIEND_LIST = set()
SUBREDDIT_LIST = set()
MULTIREDDITS = {}
COMMENT_AFTER = None
COMMENT_CACHE = {}
WHITELIST_CACHE = {}
SUBMISSION_IDS = []
QUEUE_IDS = []
LOG_IDS = []
MODMAIL_IDS = []
OPTIONS_DEFAULT = { "modmail_mute": True, "modmail_notes": False }
OPTIONS_DISABLED = { "modmail_mute": False, "modmail_notes": False }
BAN_MESSAGE = ("Bots and bot-like accounts are not welcome on /r/{0}.\n\n"
               "[I am a bot, and this action was performed automatically]"
               "(/r/{1}/wiki/index). "
               "If you wish to appeal the classification of the /u/{2} account, please "
               "[message /r/{1}]"
               "(https://www.reddit.com/message/compose?"
               "to=/r/{1}&subject=Ban%20dispute%20for%20/u/{2}%20on%20/r/{0}) "
               "rather than replying to this message.")
BAN_MESSAGE_SHORT = "Bots and bot-like accounts are not welcome on /r/{}."
PERMISSIONS_MESSAGE = ("Thank you for adding {}!\n\n"
                       "This bot works best with `access` and `posts` permissions "
                       "(current permissions: {}). "
                       "For more information, [please read this guide](/r/{}/wiki/index).")
NOTE_SHORT = "/u/{0} is [currently classified as **{1}**]({2}).\n\n"
NOTE_LONG = ("Private Moderator Note: /u/{0} is [listed on /r/{1}]({2}).\n\n"
             "- If this account is claiming to be human and isn't an obvious novelty account, "
             "we recommend asking the account owner to [message /r/{1}]"
             "(https://www.reddit.com/message/compose?"
             "to=/r/{1}&subject=Ban%20dispute%20for%20/u/{0}%20on%20/r/{3}).\n"
             "- If this account is a bot that you wish to allow, remember to [whitelist]"
             "(/r/{1}/wiki/index) it before you unban it.")
REPORT_REASON = "bot or bot-like account (moderator permissions limited to reporting)"
UNBAN_STATE = {}


def schedule(function, schedule=None, when=None):
    if schedule is not None:
        SCHEDULE[function] = schedule
    if when == "defer":
        NEXT[function] = time.time() + SCHEDULE[function]
    elif when == "next":
        NEXT[function] = 0


def run():
    now = time.time()
    next_function = min(NEXT, key=NEXT.get)
    if NEXT[next_function] > now:
        time.sleep(NEXT[next_function] - now)
    next_function()
    NEXT[next_function] = time.time() + SCHEDULE[next_function]


def expire_cache(entries, age):
    expiration = time.time() - age
    deletions = []
    for key, value in entries.items():
        if value <= expiration:
            deletions.append(key)
    for key in deletions:
        del entries[key]


def kill_switch():
    logging.info("checking kill switch")
    active = False
    counter = 0
    sleep = 60
    retries = 60
    while not active:
        try:
            permissions = HOME.moderator(ME)[0].mod_permissions
            if r.config.custom.get("node") == "primary" and "chat_operator" in permissions:
                active = False
            elif r.config.custom.get("node") == "secondary" and "chat_operator" not in permissions:
                active = False
                sleep = 600
                retries = 144
            elif permissions:
                active = True
        except Exception as e:
            logging.error("exception checking permissions: {}".format(e))
        if not active:
            logging.info("kill switch activated, sleeping")
            time.sleep(sleep)
            counter += 1
            if counter >= retries:
                logging.error("persistent kill switch, stopping")
                sys.exit(1)


def absolute_time(when):
    return datetime.fromtimestamp(when).strftime("%Y-%m-%dT%H:%M:%SZ")


def relative_time(when):
    delta = time.time() - when

    if delta < 60:
        return "just now"
    if delta < 120:
        return "a minute ago"
    if delta < 3600:
        return str(int(delta / 60)) + " minutes ago"
    if delta < 7200:
        return "an hour ago"
    return str(int(delta / 3600)) + " hours ago"


def update_status():
    global STATUS_POST

    logging.info("updating status")
    if not STATUS_POST:
        for result in HOME.search('title:"{} status"'.format(ME), sort='new'):
            if result.author == ME and result.is_self:
                STATUS_POST = result
                break
        if not STATUS_POST:
            logging.error("unable to locate status post")
            return

    last_time = None
    last_type = None
    active_bans = ""
    recent_logs = ""
    try:
        current_time = absolute_time(time.time())
        for log in HOME.mod.log(mod=ME, limit=500):
            if not last_time:
                last_time = absolute_time(log.created_utc)
                last_type = log.action
            if log.created_utc < time.time() - 86400:
                break
            recent_logs += "|{}|/r/{}|{}|\n".format(relative_time(log.created_utc),
                                                    log.subreddit, log.action)

        if FRIEND_LIST:
            active_bans = "|Active bans|{}|\n".format(len(FRIEND_LIST))
        if recent_logs:
            recent_logs = "|Time|Subreddit|Action|\n|-|-|-|\n" + recent_logs
        STATUS_POST.edit("|Attribute|Value|\n|-|-|\n{}"
                         "|Current time|{}|\n"
                         "|Last action|{}|\n"
                         "\n&nbsp;\n&nbsp;\n\n{}"
                         .format(active_bans, current_time, last_time, recent_logs))
    except Exception as e:
        logging.error("unable to update status: {}".format(e))


def friend_list(cached=False):
    global FRIEND_LIST

    if cached and FRIEND_LIST:
        return FRIEND_LIST

    logging.info("loading friends")
    friends = set(r.user.friends())
    if friends:
        FRIEND_LIST = friends
    else:
        raise RuntimeError("empty friends list")
    return FRIEND_LIST


def option(subreddit, name):
    configuration = load_configuration(subreddit)
    return configuration.get(name)


def load_configuration(subreddit):
    if subreddit in MULTIREDDITS.get("restricted", set()):
        return OPTIONS_DISABLED
    configuration = OPTIONS_DEFAULT
    try:
        wiki = subreddit.wiki[ME.lower()]
        if wiki and 0 < len(wiki.content_md) < 256:
            configuration = yaml.safe_load(wiki.content_md)
            logging.info("loaded configuration for /r/{}".format(subreddit))
    except (prawcore.exceptions.Forbidden, prawcore.exceptions.NotFound) as e:
        logging.debug("unable to read configuration for /r/{}: {}".format(subreddit, e))
    except Exception as e:
        logging.error("exception loading configuration for /r/{}: {}".format(subreddit, e))
    return configuration


def load_subreddits():
    global SUBREDDIT_LIST
    global MULTIREDDITS

    logging.info("loading subreddits")
    subreddits = set(r.user.me().moderated())
    if subreddits:
        SUBREDDIT_LIST = subreddits
    else:
        raise RuntimeError("empty subreddit list")
    MULTIREDDITS = {}
    for multireddit in r.user.multireddits():
        name = re.sub(r'\d+', '', multireddit.name)
        MULTIREDDITS[name] = set.union(MULTIREDDITS.get(name, set()), set(multireddit.subreddits))


def check_comments():
    global COMMENT_AFTER
    global COMMENT_CACHE

    logging.info("checking comments (after {}, cache {})".format(COMMENT_AFTER, len(COMMENT_CACHE)))
    comment = None
    try:
        for after in [None, COMMENT_AFTER] if COMMENT_AFTER else [None]:
            for comment in SCAN.comments(limit=100, params={"after": after}):
                if str(comment.id) in COMMENT_CACHE:
                    continue
                link = "https://www.reddit.com/comments/{}/_/{}".format(comment.submission.id, comment.id)
                consider_action(comment, link)
                # we only cache identifiers after processing successfully
                COMMENT_CACHE[str(comment.id)] = comment.created_utc
    except Exception as e:
        logging.error("exception checking comments: {}".format(e))

    COMMENT_AFTER = comment.fullname if comment and comment.created_utc > time.time() - 3600 else None


def check_submissions():
    global SUBMISSION_IDS

    logging.info("checking submissions")
    try:
        for submission in SCAN.new(limit=100):
            if str(submission.id) in SUBMISSION_IDS:
                continue
            link = "https://www.reddit.com/comments/{}".format(submission.id)
            consider_action(submission, link)
            # we only cache identifiers after processing successfully
            SUBMISSION_IDS.append(str(submission.id))
    except Exception as e:
        logging.error("exception checking submissions: {}".format(e))

    # trim cache
    if len(SUBMISSION_IDS) > 200:
        SUBMISSION_IDS = SUBMISSION_IDS[-200:]


def check_queue():
    global QUEUE_IDS

    logging.info("checking queue")
    try:
        for submission in r.subreddit("mod").mod.modqueue(limit=100, only="submissions"):
            if str(submission.id) in QUEUE_IDS:
                continue
            if submission.author in friend_list(cached=True):
                link = "https://www.reddit.com/comments/{}".format(submission.id)
                logging.info("queue hit for /u/{} in /r/{} at {}".format(submission.author,
                                                                         submission.subreddit, link))
                consider_action(submission, link)
            # we only cache identifiers after processing successfully
            QUEUE_IDS.append(str(submission.id))
    except Exception as e:
        logging.error("exception checking queue: {}".format(e))

    # trim cache
    if len(QUEUE_IDS) > 200:
        QUEUE_IDS = QUEUE_IDS[-200:]


def consider_action(post, link):
    global WHITELIST_CACHE

    account = post.author
    subreddit = post.subreddit

    if subreddit not in SUBREDDIT_LIST:
        return False

    activity = (str(account), str(subreddit))
    if activity in WHITELIST_CACHE:
        return False

    logging.info("subreddit hit /u/{} in /r/{}".format(account, subreddit))
    permissions = []
    try:
        permissions = subreddit.moderator(ME)[0].mod_permissions
        if not permissions:
            permissions.append("none")
    except Exception as e:
        logging.error("error checking moderator permissions in /r/{}: {}".format(subreddit, e))

    if is_friend(account):
        logging.info("/u/{} confirmed to be on friends list".format(account))
    else:
        logging.warning("/u/{} is not on friends list".format(account))
        return False

    try:
        if re.search("proof\\b", str(post.author_flair_css_class)):
            logging.info("/u/{} is whitelisted via flair class in /r/{}".format(account, subreddit))
            WHITELIST_CACHE[activity] = time.time()
            return False
    except Exception as e:
        logging.error("error checking flair class, failing safe for /u/{} in /r/{}: {}".format(account, subreddit, e))
        return False

    try:
        for contributor in subreddit.contributor(account):
            logging.info("/u/{} is whitelisted via approved users in /r/{}".format(account, subreddit))
            WHITELIST_CACHE[activity] = time.time()
            return False
    except Exception as e:
        logging.info("unable to check approved users for /u/{} in /r/{}: {}".format(account, subreddit, e))
        # fail safe
        if not permissions or "access" in permissions or "all" in permissions:
            logging.error("failing safe for /u/{} in /r/{}".format(account, subreddit))
            return False

    try:
        if subreddit.moderator(account):
            logging.info("/u/{} is whitelisted via moderator list in /r/{}".format(account, subreddit))
            WHITELIST_CACHE[activity] = time.time()
            return False
    except Exception as e:
        # fail safe
        logging.error("error checking moderator list, failing safe for /u/{} in /r/{}: {}".format(account, subreddit, e))
        return False

    if "access" in permissions or "all" in permissions:
        ban(account, subreddit, link, ("mail" in permissions))

    delay = int(time.time() - post.created_utc)
    if "posts" in permissions or "all" in permissions:
        try:
            if not getattr(post, "removed", None) and not getattr(post, "spam", None):
                logging.info("removing {} by /u/{} after {} seconds".format(link, account, delay))
                post.mod.remove(spam=True)
        except Exception as e:
            logging.error("error removing {}: {}".format(link, e))
    elif permissions:
        try:
            logging.info("reporting {} by /u/{} after {} seconds".format(link, account, delay))
            post.report(REPORT_REASON)
        except Exception as e:
            logging.error("error reporting {}: {}".format(link, e))
    return True


def is_friend(user):
    try:
        if type(user) == str:
            return r.redditor(user).is_friend
        else:
            return user.is_friend
    except Exception as e:
        logging.debug("exception checking is_friend for /u/{}: {}".format(user, e))
    try:
        return r.get("/api/v1/me/friends/" + str(user)) == str(user)
    except Exception as e:
        logging.debug("exception checking friends for /u/{}: {}".format(user, e))
    try:
        return user in r.user.friends()
    except Exception as e:
        logging.error("failed searching friends for /u/{}: {}".format(user, e))
    return None


def ban(account, subreddit, link, mail):
    logging.info("banning /u/{} in /r/{}".format(account, subreddit))
    try:
        for ban in subreddit.banned(account):
            logging.info("/u/{} already banned in /r/{}".format(account, subreddit))
            return
    except Exception as e:
        logging.error("error checking ban status for /u/{} in /r/{}: {}".format(account, subreddit, e))

    try:
        date = str(datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d"))
        message = BAN_MESSAGE.format(subreddit, HOME, account)
        note = "/u/{} banned by /u/{} at {} for {}".format(account, ME, date, link)
        if subreddit in MULTIREDDITS.get("restricted", set()):
            message = BAN_MESSAGE_SHORT.format(subreddit)
            note = "/u/{} banned at {} for {}".format(account, date, link)
        subreddit.banned.add(account, ban_message=message, note=note)
        logging.info("banned /u/{} in /r/{}".format(account, subreddit))
        if mail and option(subreddit, "modmail_mute"):
            logging.info("muting /u/{} in /r/{}".format(account, subreddit))
            subreddit.muted.add(account)
    except Exception as e:
        logging.error("error banning /u/{} in /r/{}: {}".format(account, subreddit, e))


def unban(account, subreddit):
    try:
        for ban in subreddit.banned(account):
            try:
                if ban.note and re.search(ME, ban.note):
                    logging.info("unbanning /u/{} on /r/{} ({})".format(account, subreddit, ban.note))
                    subreddit.banned.remove(account)
                else:
                    logging.debug("not unbanning /u/{} on /r/{} ({})".format(account, subreddit, ban.note or "[empty]"))
            except Exception as e:
                logging.error("exception unbanning /u/{} on /r/{}".format(account, subreddit))
    except prawcore.exceptions.Forbidden as e:
        logging.debug("unable to check ban for /u/{} in /r/{}: {}".format(account, subreddit, e))
    except Exception as e:
        logging.warning("error checking ban for /u/{} in /r/{}: {}".format(account, subreddit, e))


def find_canonical(name, fast=False):
    title = "overview for " + name
    url = "https://www.reddit.com/user/" + name

    for query in "url:\"{}\"".format(url), "title:\"{}\"".format(name):
        try:
            for similar in HOME.search(query):
                if similar.title == title and similar.author == ME:
                    return similar
        except Exception as e:
            logging.error("exception searching {} for canonical post: {}".format(query, e))

    if fast:
        limit = 100
    else:
        limit = 1000

    try:
        for recent in HOME.new(limit=limit):
            if recent.title == title and recent.author == ME:
                return recent
    except Exception as e:
        logging.error("exception checking recent posts for canonical post: {}".format(e))

    return None


def check_contributions():
    logging.info("checking for contributions")
    for submission in HOME.new(limit=100):
        if submission.author == ME:
            continue

        if submission.author in friend_list(cached=True):
            logging.info("contribution from friend /u/{}".format(submission.author))
            link = "https://www.reddit.com/comments/{}".format(submission.id)
            if consider_action(submission, link):
                continue

        account = None
        name = None
        post = None

        if submission.url:
            m = re.search("^https?://(?:\w+\.)?reddit\.com/u(?:ser)?/([\w-]{3,20})", submission.url)
            if m:
                account = m.group(1)

        # non-conforming posts are removed by AutoModerator so just skip them
        if not account:
            continue

        try:
            user = r.redditor(name=account)
            user_data = r.get(
                "/api/user_data_by_account_ids", {"ids": user.fullname}
            )
            name = user_data[user.fullname]["name"]
        except Exception as e:
            logging.debug("exception checking account {}: ".format(account, e))

        if not name:
            submission.mod.remove()
            comment = submission.reply("Thank you for your submission! That account does not appear to exist"
                                       " (perhaps it has already been suspended, banned, or deleted), but"
                                       " please message /r/{} if you believe this was an error.".format(HOME))
            comment.mod.distinguish()
            logging.info("contribution {} from /u/{} rejected".format(submission.permalink, submission.author))
            continue

        canonical = find_canonical(name)
        try:
            if not canonical:
                title = "overview for " + name
                url = "https://www.reddit.com/user/" + name
                post = HOME.submit(title, url=url)
                post.report("Reviewable submission from /u/{}: please approve and update flair".format(submission.author))
                post.disable_inbox_replies()
        except Exception as e:
            logging.error("exception creating canonical post: {}".format(e))

        submission.mod.remove()
        if post:
            comment = submission.reply("Thank you for your submission! We have created a new"
                                       " [entry for this account]({}).".format(post.permalink))
            comment.mod.distinguish()
            logging.info("contribution {} from /u/{} accepted for {}".format(submission.permalink, submission.author, name))
        elif canonical:
            comment = submission.reply("Thank you for your submission! It looks like we already have"
                                       " an [entry for this account]({}).".format(canonical.permalink))
            comment.mod.distinguish()
            logging.info("contribution {} from /u/{} duplicate for {}".format(submission.permalink, submission.author, name))
        else:
            comment = submission.reply("Thank you for your submission!")
            comment.mod.distinguish()
            logging.error("contribution {} from /u/{} error".format(submission.permalink, submission.author))
            HOME.message("Error processing contribution", "{}".format(submission.permalink))


def check_mail():
    logging.info("checking mail")
    try:
        for message in r.inbox.unread(limit=10):
            # log everything in inbox
            message_data = ["message {}".format(message.fullname)]
            if message.author:
                message_data.append("by /u/{}".format(message.author))
                if message.author in friend_list(cached=True):
                    message_data.append("(friend)")
            if message.subreddit:
                message_data.append("from /r/{}".format(message.subreddit))
            logging.info(" ".join(message_data))

            # skip non-messages
            if not message.fullname.startswith("t4_"):
                continue

            # handle non-subreddit messages
            if not message.subreddit:
                message.mark_read()
                if message.author in ["[deleted]", "mod_mailer", "reddit"]:
                    continue
                if message.distinguished in ["admin", "gold-auto"]:
                    continue
                if message.author in friend_list(cached=True) or message.author.moderated():
                    message.reply("I am a bot. If this is regarding {}, please message /r/{}. For anything else, please message the relevant subreddit.".format(ME, HOME))
                continue

            subreddit = message.subreddit

            # looks like an invite
            if re.search("^invitation to moderate /?(r|u|user)/[\w-]+$", str(message.subject)):
                logging.info("invited to moderate /r/{}".format(subreddit))

                for attempt in range(3):
                    try:
                        result, reason = join_subreddit(subreddit)
                        if result or reason != "error":
                            break
                    except:
                        result, reason = False, "error"

                if result:
                    message.mark_read()
                    logging.info("joined /r/{}".format(subreddit))
                    for delay in range(3):
                        time.sleep(delay)
                        moderator = subreddit.moderator(ME)
                        if moderator:
                            break
                    if not moderator:
                        raise RuntimeError("not in moderator list")
                    permissions = moderator[0].mod_permissions
                    if not "all" in permissions:
                        if not "access" in permissions or not "posts" in permissions:
                            if not permissions:
                                permissions = ["*no permissions*"]
                            logging.info("incorrect permissions ({}) on /r/{}".format(", ".join(permissions), subreddit))
                            message.reply(PERMISSIONS_MESSAGE.format(ME, ", ".join(permissions), HOME))
                else:
                    message.mark_read()
                    if reason == "error":
                        logging.info("failure accepting invite {} from /r/{}".format(message.fullname, subreddit))
                    elif reason == "moderator":
                        logging.info("already moderator on /r/{}".format(subreddit))
                    elif reason in ["banned", "prohibited"]:
                        logging.warning("ignoring invite from {} subreddit /r/{}".format(reason, subreddit))
                    else:
                        logging.info("declining invite from {} subreddit /r/{}".format(reason, subreddit))
                        message.reply(
                            "This bot isn't really needed on non-public subreddits due to very limited bot"
                            " activity. If you believe this was sent in error, please message /r/{}.".format(HOME)
                        )
            # looks like a removal
            elif re.search("^/?u/[\w-]+ has been removed as a moderator from /?(r|u|user)/[\w-]+$", str(message.subject)):
                message.mark_read()
                load_subreddits()
                schedule(load_subreddits, when="defer")
                if subreddit not in SUBREDDIT_LIST:
                    logging.info("removed as moderator from /r/{}".format(subreddit))
            # some other type of subreddit message
            else:
                message.mark_read()
    except Exception as e:
        logging.error("exception checking mail: {}".format(e))


def check_modmail():
    global MODMAIL_IDS

    logging.info("checking modmail")
    thread = None
    try:
        for thread in r.subreddit("all").modmail.conversations(limit=100):
            id = ":".join([str(thread.id), str(thread.last_mod_update), str(thread.last_user_update)])
            if id in MODMAIL_IDS:
                continue
            MODMAIL_IDS.append(id)
            account = None
            banned = False
            # fastest checks
            if thread.is_auto and thread.num_messages == 1:
                continue
            if thread.is_internal or not thread.is_repliable:
                continue
            try:
                if thread.participant:
                    account = thread.participant
                else:
                    account = thread.user
            except:
                continue
            if not account or account not in friend_list(cached=True):
                continue
            # handled check
            if ME in thread.authors:
                if next((m for m in thread.messages if m.author == ME and m.is_internal), None):
                    continue
            # home check
            if thread.owner == HOME:
                canonical = find_canonical(str(account), fast=True)
                if canonical and canonical.link_flair_text:
                    logging.info("creating note about /u/{} on /r/{}".format(account, thread.owner))
                    note = NOTE_SHORT.format(account, canonical.link_flair_text, canonical.permalink)
                    try:
                        mod_reports = canonical.mod_reports_dismissed + canonical.mod_reports
                    except AttributeError:
                        mod_reports = canonical.mod_reports
                    reports = []
                    for report, moderator in mod_reports:
                        if moderator == ME:
                            contributor = ""
                            m = re.search("\\bsubmission from (/u/[\w-]{3,20})", report)
                            if m:
                                contributor = "from {} ".format(m.group(1))
                            created = absolute_time(canonical.created_utc)
                            reports.insert(0, "- Submission {}posted {}".format(contributor, created))
                        elif not re.search("^(ignore|show|test)\\b.{0,16}$", report, re.I):
                            reports.append("- {}: {}".format(moderator, report))
                    note += "\n".join(reports)
                    thread.reply(note, internal=True)
                continue
            # banned check
            for ban in thread.owner.banned(account):
                if ban.note and re.search(ME, ban.note):
                    banned = True
            if not banned:
                continue
            # option check
            if not option(thread.owner, "modmail_notes"):
                continue
            # create note
            canonical = find_canonical(str(account), fast=True)
            if canonical:
                logging.info("creating note about /u/{} on /r/{}".format(account, thread.owner))
                thread.reply(NOTE_LONG.format(account, HOME, canonical.permalink, thread.owner), internal=True)
    except Exception as e:
        logging.error("exception checking modmail {}: {}".format(thread, e))

    # trim cache
    if len(MODMAIL_IDS) > 200:
        MODMAIL_IDS = MODMAIL_IDS[-200:]


def join_subreddit(subreddit):
    global SUBREDDIT_LIST

    try:
        if subreddit.quarantine:
            return False, "quarantined"
        elif subreddit.subreddit_type not in ["public", "restricted", "gold_only", "user"]:
            return False, subreddit.subreddit_type
        elif subreddit in MULTIREDDITS.get("prohibited", set()):
            return False, "prohibited"
    except prawcore.exceptions.Forbidden:
        return False, "quarantined"
    except prawcore.exceptions.NotFound:
        return False, "banned"
    except Exception as e:
        logging.error("exception retrieving attributes of /r/{}: {}".format(subreddit, e))
        return False, "error"

    try:
        subreddit.mod.accept_invite()
        SUBREDDIT_LIST.add(subreddit)
        if subreddit in MULTIREDDITS.get("restricted", set()):
            HOME.message("Joined restricted subreddit", "/r/{}".format(subreddit))
    except Exception as e:
        if e.items[0].error_type == "NO_INVITE_FOUND" and subreddit.moderator(ME):
            return False, "moderator"
        logging.error("exception joining /r/{}: {}".format(subreddit, e))
        return False, "error"
    else:
        return True, None


def check_state():
    global LOG_IDS
    global COMMENT_CACHE
    global WHITELIST_CACHE

    logging.info("checking state")
    try:
        recent = {}
        for log in HOME.mod.log(action="editflair", limit=100):
            # only log ids can be persistently cached, not submission ids
            if str(log.id) in LOG_IDS:
                continue
            if log.target_author != ME or not log.target_fullname.startswith("t3_"):
                continue
            # cache recent submissions and update friend list
            if not recent:
                for submission in HOME.new(limit=100):
                    recent[str(submission)] = submission
                friend_list(cached=False)
                schedule(friend_list, when="defer")
            try:
                # sync the submission and update friend list if needed
                entry = log.target_fullname[3:]
                if sync_submission(recent.get(entry, r.submission(id=entry))):
                    friend_list(cached=False)
                    schedule(friend_list, when="defer")
                # we only cache non-recent log identifiers after processing successfully
                if log.created_utc < time.time() - 600:
                    LOG_IDS.append(str(log.id))
            except Exception as e:
                logging.error("exception processing log {}: {}".format(log.id, e))
    except Exception as e:
        logging.error("exception syncing friends: {}".format(e))

    # check for pending unbans
    try:
        if not UNBAN_STATE:
            for flair in HOME.flair():
                if flair.get("user") and "unban" in flair.get("flair_css_class"):
                    subreddits = list(r.user.me().moderated())
                    if not subreddits:
                        raise RuntimeError("empty subreddit list")
                    UNBAN_STATE[flair.get("user")] = subreddits
                    schedule(check_unbans, schedule=15, when="next")
        # this is like a free kill_switch check
        schedule(kill_switch, when="defer")
    except Exception as e:
        logging.error("exception checking for pending unbans: {}".format(e))
        schedule(kill_switch, when="next")

    # trim time-based caches
    expire_cache(COMMENT_CACHE, 3600)
    expire_cache(WHITELIST_CACHE, 3600)

    # trim cache
    if len(LOG_IDS) > 200:
        LOG_IDS = LOG_IDS[-200:]


def sync_submission(submission):
    account = None
    if submission.url:
        m = re.search("/u(?:ser)?/([\w-]+)", submission.url)
        if m:
            account = m.group(1)
    if account and submission.link_flair_text != "pending":
        user = r.redditor(account)
        if submission.link_flair_text == "banned" and user not in friend_list(cached=True):
            try:
                user.friend()
                logging.info("added friend /u/{}".format(user))
            except praw.exceptions.RedditAPIException as e:
                if e.items[0].error_type == "USER_DOESNT_EXIST":
                    logging.debug("unable to add friend /u/{}: {}".format(user, e))
                    return False
                else:
                    logging.error("error adding friend /u/{}: {}".format(user, e))
            except Exception as e:
                logging.error("error adding friend /u/{}: {}".format(user, e))
            return True
        elif submission.link_flair_text != "banned" and user in friend_list(cached=True):
            try:
                user.unfriend()
                logging.info("removed friend /u/{}".format(user))
                if submission.link_flair_text not in ["inactive", "retired"]:
                    HOME.flair.set(user, css_class="unban")
            except Exception as e:
                logging.error("error removing friend /u/{}: {}".format(user, e))
            return True
    return False


def check_unbans():
    logging.info("checking unbans")
    if not UNBAN_STATE:
        return
    try:
        pause = time.time() + 10
        account = next(iter(UNBAN_STATE))
        logging.info("processing unban for /u/{} ({} subreddits remaining)".format(account, len(UNBAN_STATE[account])))
        while UNBAN_STATE[account] and time.time() < pause:
            unban(account, UNBAN_STATE[account].pop(0))
        if not UNBAN_STATE[account]:
            logging.info("finished unban for /u/{}".format(account))
            HOME.flair.delete(account)
            del UNBAN_STATE[account]
            if not UNBAN_STATE:
                schedule(check_unbans, schedule=86400, when="defer")
    except Exception as e:
        logging.error("exception checking unbans: {}".format(e))


if __name__ == "__main__":
    SCHEDULE = {
        kill_switch: 120,
        load_subreddits: 3600,
        check_comments: 5,
        check_submissions: 30,
        check_queue: 60,
        check_mail: 120,
        check_modmail: 30,
        check_contributions: 60,
        check_unbans: 86400,
        check_state: 300,
        friend_list: 3600,
        update_status: 600,
    }
    NEXT = SCHEDULE.copy()

    try:
        logging.info("starting")
        schedule(kill_switch, when="next")
        schedule(load_subreddits, when="next")
        while True:
            run()
    except KeyboardInterrupt:
        logging.error("received SIGINT from keyboard, stopping")
        sys.exit(1)
    except Exception as e:
        logging.error("site error: {}".format(e))
        time.sleep(10 if min(NEXT.values()) > max(SCHEDULE.values()) else 60)
        sys.exit(1)

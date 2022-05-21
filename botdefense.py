#!/usr/bin/env python3.7

import os
import sys
import logging
import re
import time
from datetime import datetime
import random
import praw
import prawcore.exceptions
import requests
import yaml


# global data
STATUS_POST = None
FRIEND_LIST = set()
INACTIVE_LIST = set()
SUBREDDIT_LIST = set()
MULTIREDDITS = {}
COMMENT_AFTER = None
COMMENT_CACHE = {}
LOG_CACHE = {}
CONTRIBUTION_LIMIT = 0
NOTE_FAILURE_CACHE = {}
NOTE_LIMIT = 0
WHITELIST_CACHE = {}
SUBMISSION_IDS = []
QUEUE_LIST = []
QUEUE_COUNTER = 0
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
APPEAL_MESSAGE = ("Your classification appeal has been received and will be reviewed by a "
                  "moderator. If accepted, the result of your appeal will apply to any "
                  "subreddit using /r/{}.\n\n*This is an automated message.*")
REPORT_REASON = "bot or bot-like account (moderator permissions limited to reporting)"
UNBAN_STATE = {}


# setup logging
class LengthFilter(logging.Filter):
    retry = None

    def filter(self, record):
        if record.funcName == '_do_retry' and record.msg.endswith('/about/modqueue/'):
            m = re.search(r'/r/([\w-]+\+)+[\w-]+/', record.msg)
            if m:
                record.msg = record.msg.replace(m.group(0), f'/r/[{m.group(0).count("+") + 1} subreddits]/')
                if self.retry and self.retry[0] == hash(m.group(0)) and 60 < time.time() - self.retry[1] < 300:
                    split_subreddits()
                    record.msg += " (splitting subreddits)"
                self.retry = (hash(m.group(0)), time.time())
        return True


os.environ['TZ'] = 'UTC'
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(funcName)s | %(message)s',
                    datefmt='%Y-%m-%dT%H:%M:%S')
logging.getLogger('prawcore').addFilter(LengthFilter())


# setup reddit
try:
    assert praw.__version__.startswith('7.6.')
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
        STATUS_POST.edit(body="|Attribute|Value|\n|-|-|\n{}"
                         "|Current time|{}|\n"
                         "|Last action|{}|\n"
                         "\n&nbsp;\n&nbsp;\n\n{}"
                         .format(active_bans, current_time, last_time, recent_logs))
    except Exception as e:
        logging.error("unable to update status: {}".format(e))


def load_flair():
    global FRIEND_LIST
    global INACTIVE_LIST

    logging.info("loading flair")
    friends = set()
    inactive = set()
    try:
        for flair in r.user.me().subreddit.flair():
            if not flair.get("user"):
                continue
            if flair.get("flair_css_class") == "banned":
                friends.add(flair["user"])
            elif flair.get("flair_css_class") == "inactive":
                inactive.add(flair["user"])
    except Exception as e:
        logging.error("exception loading flair: {}".format(e))
        raise
    if friends:
        FRIEND_LIST = friends
        INACTIVE_LIST = inactive
    else:
        raise RuntimeError("empty friends list")
    logging.info("loaded {} friends".format(len(friends)))
    logging.info("loaded {} inactive".format(len(inactive)))


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


def split_subreddits():
    global QUEUE_LIST

    results = []
    try:
        subreddits = list(filter(lambda s: ':' not in str(s) and s.subreddit_type != "private", SUBREDDIT_LIST))
        if not subreddits:
            return
        random.shuffle(subreddits)
        subreddits = map(str, subreddits)
        current = next(subreddits)
        for subreddit in subreddits:
            # queue requests are limited to 500 subreddits
            # bad request errors start around 6358 bytes for queue requests with limit=100, only="submissions"
            if current.count('+') + 1 == 500 or len(current) + len(subreddit) > 6272:
                results.append(current)
                current = subreddit
            else:
                current += '+' + subreddit
        results.append(current)
    except Exception as e:
        logging.error("error slicing subreddits: {}".format(e))
        return
    QUEUE_LIST = results


def load_subreddits():
    global SUBREDDIT_LIST
    global MULTIREDDITS

    logging.info("loading subreddits")
    subreddits = set(r.user.me().moderated())
    if subreddits:
        SUBREDDIT_LIST = subreddits
        split_subreddits()
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
                if comment.created_utc <= time.time() - 3600:
                    break
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
    global QUEUE_LIST
    global QUEUE_COUNTER

    logging.info("checking queue")
    try:
        if not QUEUE_LIST:
            return
        subreddits = QUEUE_LIST[QUEUE_COUNTER % len(QUEUE_LIST)]
        for submission in r.subreddit(subreddits).mod.modqueue(limit=100, only="submissions"):
            if submission.author in FRIEND_LIST:
                link = "https://www.reddit.com/comments/{}".format(submission.id)
                logging.info("queue hit for /u/{} in /r/{} at {}".format(submission.author,
                                                                         submission.subreddit, link))
                consider_action(submission, link)
    except Exception as e:
        error = str(e)
        if error.startswith("<html>"):
            error = error.replace("\n", "")
        logging.error("exception checking queue: {}".format(error))
    QUEUE_COUNTER += 1


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
        if (not permissions or "access" in permissions or "all" in permissions) and subreddit.subreddit_type != "user":
            for contributor in subreddit.contributor(account):
                logging.info("/u/{} is whitelisted via approved users in /r/{}".format(account, subreddit))
                WHITELIST_CACHE[activity] = time.time()
                return False
    except Exception as e:
        logging.error("error checking approved users, failing safe for /u/{} in /r/{}: {}".format(account, subreddit, e))
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

    if getattr(post, "removed", None) or getattr(post, "spam", None):
        return True

    delay = int(time.time() - post.created_utc)
    if "posts" in permissions or "all" in permissions:
        try:
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
        if isinstance(user, praw.models.Redditor):
            return user.is_friend
    except Exception as e:
        logging.debug("exception checking is_friend for /u/{}: {}".format(user, e))
    try:
        return r.get(path=f"/api/v1/me/friends/{user}") == str(user)
    except Exception as e:
        print(vars(e))
        if type(e) == praw.exceptions.RedditAPIException and e.items[0].error_type in ["NOT_FRIEND", "USER_DOESNT_EXIST"]:
            return False
        logging.warning("exception checking friends for /u/{}: {}".format(user, e))
    return None


def add_friend(user):
    global FRIEND_LIST

    user.friend()
    r.user.me().subreddit.flair.set(user, text="banned", css_class="banned")
    FRIEND_LIST.add(user)
    if user in INACTIVE_LIST:
        INACTIVE_LIST.remove(user)


def remove_friend(user):
    global FRIEND_LIST

    try:
        user.unfriend()
    except praw.exceptions.RedditAPIException as e:
        if e.items[0].error_type != "NOT_FRIEND":
            raise
    except:
        raise
    r.user.me().subreddit.flair.delete(user)
    if user in FRIEND_LIST:
        FRIEND_LIST.remove(user)


def add_inactive(user):
    global INACTIVE_LIST

    r.user.me().subreddit.flair.set(user, text="inactive", css_class="inactive")
    INACTIVE_LIST.add(user)


def remove_inactive(user):
    global INACTIVE_LIST

    r.user.me().subreddit.flair.delete(user)
    if user in INACTIVE_LIST:
        INACTIVE_LIST.remove(user)


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
            for similar in HOME.search(query, limit=250):
                if similar.title.lower() == title.lower() and similar.author == ME:
                    return similar
        except Exception as e:
            logging.error("exception searching {} for canonical post: {}".format(query, e))

    try:
        for recent in HOME.new(limit=100 if fast else 1000):
            if recent.title.lower() == title.lower() and recent.author == ME:
                logging.info("using recent result for {}".format(name))
                return recent
            if recent.created_utc < time.time() - 86400:
                break
    except Exception as e:
        logging.error("exception checking recent posts for canonical post: {}".format(e))

    try:
        query = { "q": f'"{name}"', "author": ME, "subreddit": f'{HOME}', "limit": 100 }
        response = requests.get("https://api.pushshift.io/reddit/submission/search", timeout=15, params=query)
        response.raise_for_status()
        results = response.json()
        if type(results) is dict and type(results.get("data")) is list:
            for result in results["data"]:
                if type(result) is dict and result.get("id") and result.get("url") == url:
                    similar = r.submission(result["id"])
                    if getattr(similar, "removed", None) or getattr(similar, "spam", None):
                        continue
                    if similar.title.lower() == title.lower() and similar.author == ME:
                        logging.info("using Pushshift result for {}".format(name))
                        return similar
    except Exception as e:
        logging.error("exception querying Pushshift for canonical post: {}".format(e))

    return None


def process_contribution(submission, result, note=None, reply=None, crosspost=None):
    try:
        submission.mod.remove()
    except Exception as e:
        logging.warning("exception removing contribution {}: {}".format(submission.permalink, e))
    try:
        if reply:
            comment = submission.reply(body=reply)
            comment.mod.distinguish()
    except Exception as e:
        logging.warning("exception replying to contribution {}: {}".format(submission.permalink, e))
    try:
        if crosspost:
            duplicates = set(crosspost.duplicates())
            for subreddit in MULTIREDDITS.get("crossposts", set()):
                available = False
                for post in duplicates:
                    if post.subreddit == subreddit and not post.removed_by_category and not post.archived and post.title == crosspost.title and post.author == ME:
                        available = True
                        break
                if not available:
                    # submissions from private subreddits cannot be crossposted
                    if crosspost.subreddit.subreddit_type == "private":
                        subreddit.submit(crosspost.title, url=submission.url, send_replies=False)
                    else:
                        crosspost.crosspost(subreddit, send_replies=False)
    except Exception as e:
        logging.warning("exception crossposting {}: {}".format(crosspost.permalink, e))
    note = " " + note if note else ""
    log = "contribution {} from /u/{} with flair {} {}{}".format(submission.permalink, submission.author, submission.link_flair_text, result, note)
    if result == "error":
        logging.error(log)
        HOME.message("Error processing contribution", "{}".format(submission.permalink))
    else:
        logging.info(log)


def check_contributions():
    global CONTRIBUTION_LIMIT

    logging.info("checking for contributions")

    # process oldest submissions first
    submissions = []
    try:
        # check submissions
        newest = None
        for submission in r.multireddit(redditor=ME, name="contributions").new(limit=1000):
            if newest is None:
                newest = submission
            if submission.created_utc < CONTRIBUTION_LIMIT or submission.created_utc < time.time() - 86400:
                break
            if submission.author != ME:
                submissions.insert(0, submission)
        # set future limit
        if submissions:
            CONTRIBUTION_LIMIT = submissions[0].created_utc - 600
        elif newest:
            CONTRIBUTION_LIMIT = newest.created_utc - 3600
    except Exception as e:
        logging.error("exception checking submissions: {}".format(e))

    # process submissions for a limited period of time
    pause = time.time() + 60
    moderators = None
    for submission in submissions:
        if time.time() >= pause:
            break

        if submission.author in FRIEND_LIST:
            logging.info("contribution from friend /u/{}".format(submission.author))
            link = "https://www.reddit.com/comments/{}".format(submission.id)
            if consider_action(submission, link):
                continue

        # require account
        account = None
        if submission.url:
            m = re.search("^https?://(?:\w+\.)?reddit\.com/u(?:ser)?/([\w-]{3,20})", submission.url)
            if m:
                account = m.group(1)
        if not account:
            continue

        # fetch moderator list once
        if moderators is None:
            moderators = list(map(str, HOME.moderator()))

        # wait for flair unless exempted
        if not (submission.link_flair_text or submission.author in moderators or submission.subreddit.subreddit_type == "private"):
            continue

        name = None
        try:
            user = r.get(path=f"/user/{account}/about/")
            name = user.name
        except Exception as e:
            logging.debug("exception checking account {}: ".format(account, e))

        if not name or getattr(user, "is_suspended", None):
            reply = ("Thank you for your submission! That account does not appear to exist"
                     " (perhaps it has already been suspended, banned, or deleted), but"
                     " please message /r/{} if you believe this was an error.".format(HOME))
            process_contribution(submission, "rejected", reply=reply)
            continue

        if submission.author == user and submission.author not in moderators:
            process_contribution(submission, "blocked", note="(submitter account)")
            HOME.banned.add(submission.author, ban_message="Submitting your own account is not allowed.",
                            note="submitted their own account {}".format(submission.permalink))
            continue

        if user in moderators and submission.author not in moderators:
            process_contribution(submission, "blocked", note="(moderator account)")
            HOME.banned.add(submission.author, ban_message="Submitting a moderator account is not allowed.",
                            note="submitted moderator account {}".format(submission.permalink))
            continue

        approved = True
        try:
            for report_name in ["mod_reports", "mod_reports_dismissed"]:
                value = getattr(submission, report_name, None)
                if value:
                    for report, moderator in value:
                        if moderator == "AutoModerator":
                            logging.info("contribution {} from /u/{} reported for \"{}\"".format(submission.permalink, submission.author, report))
                            approved = False
            if not approved and submission.author.is_mod:
                minimum = option(HOME, "contribution_minimum_subscribers")
                if minimum:
                    moderated = submission.author.moderated()
                    if moderated and moderated[0].subscribers >= minimum:
                        approved = True
        except Exception as e:
            logging.warning("exception reviewing /u/{} for {}: {}".format(submission.author, submission.permalink, e))

        canonical = find_canonical(name)
        post = None
        try:
            if approved and not canonical:
                css_class = "pending"
                report_type = "Reviewable"
                if submission.link_flair_text:
                    m = re.search("^contribution-(\w+)$", submission.link_flair_text)
                    if m:
                        css_class = m.group(1)
                        report_type = css_class.capitalize()
                flair = None
                try:
                    for template in HOME.flair.link_templates:
                        if template.get("css_class") == css_class:
                            flair = template.get("id")
                            break
                except Exception as e:
                    logging.warning("exception searching link templates: {}".format(e))
                title = "overview for " + name
                url = "https://www.reddit.com/user/" + name
                post = HOME.submit(title, url=url, send_replies=False, flair_id=flair)
                for attempt in range(3):
                    try:
                        post.report("{} submission https://redd.it/{} from /u/{}".format(report_type, submission.id, submission.author))
                        if css_class != "pending" and flair:
                            sync_submission(post)
                            post.mod.approve()
                        break
                    except Exception as e:
                        logging.error("exception reporting canonical post: {}".format(e))
        except Exception as e:
            logging.error("exception creating canonical post: {}".format(e))

        if post:
            reply = ("Thank you for your submission! We have created a new"
                     " [entry for this account]({}).".format(post.permalink))
            process_contribution(submission, "accepted", note="for {}".format(name), reply=reply, crosspost=post)
        elif canonical:
            reply = ("Thank you for your submission! It looks like we already have"
                     " an [entry for this account]({}).".format(canonical.permalink))
            process_contribution(submission, "duplicate", note="for {}".format(name), reply=reply, crosspost=canonical)
        elif not approved:
            reply = "Submissions must be made by approved users."
            process_contribution(submission, "denied", reply=reply)
            continue
        else:
            reply = "Thank you for your submission!"
            process_contribution(submission, "error", reply=reply)


def check_notes():
    global NOTE_FAILURE_CACHE
    global NOTE_LIMIT

    logging.info("checking for notes")
    if not MULTIREDDITS.get("notes"):
        return

    # process oldest comments first
    comments = []
    try:
        # check comments
        newest = None
        for comment in r.multireddit(redditor=ME, name="contributions").comments(limit=1000):
            if newest is None:
                newest = comment
            if comment.created_utc < NOTE_LIMIT or comment.created_utc < time.time() - 28800:
                break
            if comment.locked and comment.author != ME:
                if comment.created_utc < time.time() - 21600:
                    logging.warning("unable to create note for {}".format(comment.permalink))
                    comment.mod.unlock()
                else:
                    comments.insert(0, comment)
        # set future limit
        if comments:
            NOTE_LIMIT = comments[0].created_utc - 600
        elif newest:
            NOTE_LIMIT = newest.created_utc - 3600
    except Exception as e:
        logging.error("exception checking comments: {}".format(e))

    # process comments for a limited period of time
    pause = time.time() + 60
    skipped = set()
    for comment in comments:
        if time.time() >= pause:
            break

        # skip new comments
        if comment.created_utc > time.time() - 120:
            continue

        try:
            account = None
            if comment.submission.url:
                m = re.search("^https?://(?:\w+\.)?reddit\.com/u(?:ser)?/([\w-]{3,20})", comment.submission.url)
                if m:
                    account = m.group(1)
            if not account:
                comment.mod.unlock()
                continue

            # skip recent failures
            if NOTE_FAILURE_CACHE.get(account):
                skipped.add(comment.id)
                continue

            canonical = None
            if comment.subreddit == HOME and comment.submission.author == ME:
                canonical = comment.submission
            else:
                canonical = find_canonical(account)
            if not canonical:
                NOTE_FAILURE_CACHE[account] = time.time()
                logging.warning("unable to find canonical post for {}".format(comment.permalink))
                continue

            for post in set(canonical.duplicates()):
                if post.author != ME:
                    continue
                if post.subreddit not in MULTIREDDITS.get("notes", set()):
                    continue
                if post == comment.submission:
                    continue
                attribution = "Note from /u/{} at {}".format(comment.author, comment.permalink)
                logging.info("creating note for {} on {}".format(comment.permalink, post.permalink))
                try:
                    post.reply(body="{}:\n\n---\n\n{}".format(attribution, comment.body))
                except praw.exceptions.RedditAPIException as e:
                    logging.warning("exception creating note for {}, trying again with short note: {}".format(comment.permalink, e))
                    try:
                        post.reply(body="{}.".format(attribution))
                    except Exception as e:
                        logging.error("exception creating note for {}: {}".format(comment.permalink, e))
                except Exception as e:
                    logging.error("exception creating note for {}: {}".format(comment.permalink, e))
            comment.mod.unlock()
        except Exception as e:
            logging.error("exception checking for notes: {}".format(e))

    if skipped:
        logging.info("skipped due to recent failure: {}".format(", ".join(sorted(skipped))))


def check_mail():
    logging.info("checking mail")
    try:
        for message in r.inbox.unread(limit=10):
            # log everything in inbox
            message_data = ["message {}".format(message.fullname)]
            if message.author:
                message_data.append("by /u/{}".format(message.author))
                if message.author in FRIEND_LIST:
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
                if message.distinguished in ["admin", "gold-auto"]:
                    continue
                if message.author in ["[deleted]", "mod_mailer"]:
                    continue
                if message.author in FRIEND_LIST or message.author.moderated():
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
                    elif reason in ["banned", "prohibited", "quarantined"]:
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
            modmail_id = ":".join([str(thread.id), str(thread.last_mod_update), str(thread.last_user_update)])
            if modmail_id in MODMAIL_IDS:
                continue
            MODMAIL_IDS.append(modmail_id)
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
            if not account or account not in FRIEND_LIST:
                continue
            # handled check
            if ME in thread.authors:
                # workaround for https://github.com/praw-dev/praw/issues/1870
                if next((m for m in thread.owner.modmail(thread.id).messages if m.author == ME and m.is_internal), None):
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
                    notes = []
                    for report, moderator in mod_reports:
                        if moderator == ME:
                            contributor = ""
                            m = re.search("\\bsubmission from (/u/[\w-]{3,20})", report)
                            if m:
                                contributor = "from {} ".format(m.group(1))
                            created = absolute_time(canonical.created_utc)
                            notes.insert(0, "- Submission {}posted {}".format(contributor, created))
                        elif not re.search("^(ignore|show|test)\\b.{0,16}$", report, re.I):
                            notes.append("- {}: {}".format(moderator, report))
                    for post in set(canonical.duplicates()):
                        if post.author != ME:
                            continue
                        if post.subreddit not in MULTIREDDITS.get("notes", set()):
                            continue
                        authors = set()
                        for comment in post.comments.list():
                            if isinstance(comment, praw.models.MoreComments) or comment.body == "[deleted]":
                                continue
                            author = comment.author
                            if author == ME:
                                m = re.search("\\bfrom /u/([\w-]{3,20})", comment.body)
                                if m:
                                    author = m.group(1)
                            if author:
                                authors.add(str(author))
                        if authors:
                            notes.append("- [Notes from {}]({})".format(", ".join(sorted(authors)), post.permalink))
                    note += "\n".join(notes)
                    if canonical.link_flair_text == "banned":
                        try:
                            if thread.user.mute_status.get("muteCount") == 0:
                                thread.reply(body=APPEAL_MESSAGE.format(HOME), author_hidden=True)
                        except Exception as e:
                            logging.warning("exception handling appeal {}: {}".format(thread, e))
                    thread.reply(body=note, internal=True)
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
                thread.reply(body=NOTE_LONG.format(account, HOME, canonical.permalink, thread.owner), internal=True)
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
            HOME.message("Invitation from prohibited subreddit", "/r/{}".format(subreddit))
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
    global COMMENT_CACHE
    global LOG_CACHE
    global WHITELIST_CACHE

    logging.info("checking state")
    try:
        edited = {}
        # get recent actions that may indicate a state change
        for action in ["approvelink", "editflair"]:
            for log in HOME.mod.log(action=action, limit=500):
                # only log ids can be persistently cached, not submission ids
                if str(log.id) in LOG_CACHE:
                    continue
                if log.created_utc <= time.time() - 86400:
                    break
                if log.target_author != ME or not log.target_fullname.startswith("t3_"):
                    continue
                if edited.get(log.target_fullname):
                    edited[log.target_fullname].append(str(log.id))
                else:
                    edited[log.target_fullname] = [str(log.id)]
        for submission in r.info(fullnames=edited.keys()):
            try:
                # skip removed and deleted submissions
                if getattr(submission, "removed_by_category", None):
                    continue
                # sync the submission
                sync_submission(submission)
                # we only cache log identifiers after processing successfully
                for log_id in edited[submission.fullname]:
                    LOG_CACHE[log_id] = time.time()
            except Exception as e:
                logging.error("exception processing log {}: {}".format(log.id, e))
    except Exception as e:
        logging.error("exception syncing friends: {}".format(e))

    # check for pending unbans
    try:
        if not UNBAN_STATE:
            for flair in HOME.flair():
                if flair.get("user") and flair.get("flair_css_class") == "unban":
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
    expire_cache(LOG_CACHE, 86400)
    expire_cache(NOTE_FAILURE_CACHE, 3600)
    expire_cache(WHITELIST_CACHE, 3600)


def sync_submission(submission):
    account = None
    if submission.url:
        m = re.search("/u(?:ser)?/([\w-]+)", submission.url)
        if m:
            account = m.group(1)
    if account:
        user = r.redditor(account)
        # pending
        if submission.link_flair_text == "pending":
            return
        # banned
        elif submission.link_flair_text == "banned":
            if user in FRIEND_LIST:
                return
            try:
                add_friend(user)
                logging.info("added friend /u/{}".format(user))
            except praw.exceptions.RedditAPIException as e:
                if e.items[0].error_type == "USER_DOESNT_EXIST":
                    logging.debug("unable to add friend /u/{}: {}".format(user, e))
                    return
                else:
                    logging.error("error adding friend /u/{}: {}".format(user, e))
            except Exception as e:
                logging.error("error adding friend /u/{}: {}".format(user, e))
            return
        # inactive
        elif submission.link_flair_text == "inactive":
            if user in INACTIVE_LIST:
                return
            try:
                if user in FRIEND_LIST:
                    remove_friend(user)
                    logging.info("removed friend /u/{}".format(user))
                add_inactive(user)
                logging.info("added inactive /u/{}".format(user))
            except Exception as e:
                logging.error("error adding inactive /u/{}: {}".format(user, e))
                HOME.message("Error adding inactive", "/u/{}".format(user))
            return
        # neither banned nor inactive
        elif user in FRIEND_LIST or user in INACTIVE_LIST:
            try:
                if user in FRIEND_LIST:
                    remove_friend(user)
                    logging.info("removed friend /u/{}".format(user))
            except Exception as e:
                logging.error("error removing friend /u/{}: {}".format(user, e))
                HOME.message("Error removing friend", "/u/{}".format(user))
            try:
                if user in INACTIVE_LIST:
                    remove_inactive(user)
                    logging.info("removed inactive /u/{}".format(user))
            except Exception as e:
                logging.error("error removing inactive /u/{}: {}".format(user, e))
                HOME.message("Error removing inactive", "/u/{}".format(user))
            try:
                if submission.link_flair_text in ["declined", "organic", "service"]:
                    HOME.flair.set(user, css_class="unban")
            except Exception as e:
                logging.error("error adding unban /u/{}: {}".format(user, e))
                HOME.message("Error adding unban", "/u/{}".format(user))


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
        check_comments: 5,
        check_contributions: 60,
        check_mail: 120,
        check_modmail: 30,
        check_notes: 120,
        check_queue: 20,
        check_state: 300,
        check_submissions: 30,
        check_unbans: 86400,
        kill_switch: 120,
        load_flair: 86400,
        load_subreddits: 86400,
        update_status: 900,
    }
    NEXT = SCHEDULE.copy()

    try:
        logging.info("starting")
        schedule(kill_switch, when="next")
        schedule(load_flair, when="next")
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

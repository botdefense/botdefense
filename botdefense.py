#!/usr/bin/env python3.7

import logging
import os
import random
import re
import sys
import time
from copy import deepcopy
from datetime import datetime

import praw
import prawcore.exceptions
import yaml


# global data
STATUS_POST = None
FRIEND_LIST = set()
INACTIVE_LIST = set()
SUBREDDITS = {}
COMMENT_AFTER = None
COMMENT_CACHE = {}
LOG_CACHE = {}
CONTRIBUTION_LIMIT = 0
NOTE_FAILURE_CACHE = {}
NOTE_UNLOCKED_CACHE = {}
WHITELIST_CACHE = {}
SUBMISSION_CACHE = {}
MODMAIL_IDS = []
NEW_FRIENDS = []
UNBAN_STATE = {}
OPTIONS_DEFAULT = { "modmail_mute": True, "modmail_notes": False }
OPTIONS_DISABLED = { "modmail_mute": False, "modmail_notes": False }
CONFIGURATION = {}
CONFIGURATION_DEFAULT = {
    "ban_message": ("Bots and bot-like accounts are not welcome on /r/{subreddit}.\n\n"
                    "[I am a bot, and this action was performed automatically]"
                    "(/r/{home}/wiki/index). "
                    "If you wish to appeal the classification of the /u/{account} account, please "
                    "[message /r/{home}]"
                    "(https://www.reddit.com/message/compose?"
                    "to=/r/{home}&subject=Ban%20dispute%20for%20/u/{account}%20on%20/r/{subreddit}) "
                    "rather than replying to this message."),
    "ban_note": "/u/{account} banned by /u/{me} at {date} for {reason}",
    "permissions_message": ("Thank you for adding {me}!\n\n"
                            "This bot works best with `access` and `posts` permissions "
                            "(current permissions: {permissions}). "
                            "For more information, [please read this guide](/r/{home}/wiki/index)."),
    "note_home": "/u/{account} is [currently classified as **{classification}**]({link}).\n\n",
    "note_other": ("Private Moderator Note: /u/{account} is [listed on /r/{home}]({link}).\n\n"
                   "- If this account is claiming to be human and isn't an obvious novelty account, "
                   "we recommend asking the account owner to [message /r/{home}]"
                   "(https://www.reddit.com/message/compose?"
                   "to=/r/{home}&subject=Ban%20dispute%20for%20/u/{account}%20on%20/r/{subreddit}).\n"
                   "- If this account is a bot that you wish to allow, remember to [whitelist]"
                   "(/r/{home}/wiki/index) it before you unban it."),
    "appeal_message": ("Your classification appeal has been received and will be reviewed by a "
                       "moderator. If accepted, the result of your appeal will apply to any "
                       "subreddit using /r/{home}.\n\n*This is an automated message.*"),
    "report_reason": "bot or bot-like account (moderator permissions limited to reporting)",
}

# setup logging
class LengthFilter(logging.Filter):
    def filter(self, record):
        if record.funcName == '_do_retry' and re.search(r'/about/(log|modqueue)/$', record.msg):
            m = re.search(r'/r/([\w:-]+\+)+[\w:-]+/', record.msg)
            if m:
                record.msg = record.msg.replace(m.group(0), f'/r/[{m.group(0).count("+") + 1} subreddits]/')
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


def member(name, element):
    return str(element) in SUBREDDITS.get(name, set())


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


def short_link(post):
    if post.fullname.startswith("t1_"):
        return f"https://www.reddit.com/comments/{post.link_id[3:]}/_/{post.id}"
    elif post.fullname.startswith("t3_"):
        return f"https://www.reddit.com/comments/{post.id}"
    return None


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


def option(subreddit, value, default=None):
    if subreddit == HOME and CONFIGURATION:
        return CONFIGURATION.get(value, default)
    options = load_configuration(subreddit)
    return options.get(value, default)


def load_configuration(subreddit=None):
    global CONFIGURATION

    if subreddit is None:
        subreddit = HOME
    if member("restricted", subreddit):
        return OPTIONS_DISABLED
    options = deepcopy(OPTIONS_DEFAULT)
    if subreddit == HOME:
        options.update(CONFIGURATION_DEFAULT)
    try:
        wiki = subreddit.wiki[ME.lower()]
        if wiki and 0 < len(wiki.content_md) < 4096:
            wiki_options = yaml.safe_load(wiki.content_md)
            options.update(wiki_options)
            logging.info("loaded configuration for /r/{}".format(subreddit))
            if subreddit == HOME:
                CONFIGURATION = options
    except (prawcore.exceptions.Forbidden, prawcore.exceptions.NotFound) as e:
        logging.debug("unable to read configuration for /r/{}: {}".format(subreddit, e))
    except Exception as e:
        logging.error("exception loading configuration for /r/{}: {}".format(subreddit, e))
    return options


def random_subreddits(subreddits, length=6272, separator='+'):
    try:
        # queue requests are limited to 500 subreddits
        sample = separator.join(random.sample(subreddits, k=min(500, len(subreddits))))
        # bad request errors start at 6358 bytes for queue requests with limit=100, only="submissions"
        if len(sample) > length:
            sample = sample[:sample.rindex(separator, 0, length+1)]
        return sample
    except Exception as e:
        logging.error("error slicing subreddits: {}".format(e))
        return None


def load_subreddits():
    global SUBREDDITS

    logging.info("loading subreddits")
    SUBREDDITS = { "moderated": set(), "nsfw": set() }
    start = time.time()
    for subreddit in r.user.me().moderated():
        SUBREDDITS["moderated"].add(str(subreddit))
        elapsed = time.time() - start
        if elapsed < 60 and subreddit.over_18:
            SUBREDDITS["nsfw"].add(str(subreddit))
    if not SUBREDDITS.get("moderated"):
        raise RuntimeError("empty subreddit list")
    if elapsed >= 60:
        logging.warning("time limit exceeded")
    for multireddit in r.user.multireddits():
        name = re.sub(r'\d+', '', multireddit.name)
        multireddit.subreddits = set(map(str, multireddit.subreddits))
        SUBREDDITS[name] = set.union(SUBREDDITS.get(name, set()), multireddit.subreddits)


def check_comments():
    global COMMENT_AFTER
    global COMMENT_CACHE

    logging.info("checking comments (after {}, cache {})".format(COMMENT_AFTER, len(COMMENT_CACHE)))
    comment = None
    try:
        entries = {}
        for after in [None, COMMENT_AFTER] if COMMENT_AFTER else [None]:
            for comment in SCAN.comments(limit=100, params={"after": after}):
                if comment.id in COMMENT_CACHE:
                    continue
                if comment.created_utc <= time.time() - 3600:
                    break
                if member("moderated", comment.subreddit):
                    group = (str(comment.author), str(comment.subreddit))
                    if group not in entries:
                        entries[group] = []
                    entries[group].append(comment)
                    COMMENT_CACHE[comment.id] = comment.created_utc
        for comments in entries.values():
            consider_action("check_comments", comments)
    except Exception as e:
        logging.error("exception checking comments: {}".format(e))

    COMMENT_AFTER = comment.fullname if comment and comment.created_utc > time.time() - 3600 else None


def check_submissions():
    global SUBMISSION_CACHE

    logging.info("checking submissions")
    try:
        for submission in SCAN.new(limit=100):
            if submission.id in SUBMISSION_CACHE:
                continue
            if submission.created_utc <= time.time() - 3600:
                break
            if member("moderated", submission.subreddit):
                consider_action("check_submissions", submission)
                SUBMISSION_CACHE[submission.id] = submission.created_utc
    except Exception as e:
        logging.error("exception checking submissions: {}".format(e))


def check_queue():
    global SUBMISSION_CACHE

    logging.info("checking queue")
    try:
        # modqueue query
        subreddits = SUBREDDITS.get("moderated", set())
        total_subreddits = len(subreddits)
        exclusions = option(HOME, "modqueue_exclusions", [])
        if exclusions:
            subreddits = subreddits.difference(exclusions)
        query = random_subreddits(list(subreddits))
        for submission in r.subreddit(query).mod.modqueue(limit=100, only="submissions"):
            if submission.id in SUBMISSION_CACHE:
                continue
            if submission.author in FRIEND_LIST:
                consider_action("check_queue", submission)
                SUBMISSION_CACHE[submission.id] = submission.created_utc
        # excluded subreddits
        if random.random() < 500 / total_subreddits:
            query = random_subreddits(exclusions)
            for log in r.subreddit(query).mod.log(limit=500):
                if not log.target_fullname or not log.target_fullname.startswith("t3_"):
                    continue
                if log.target_fullname[3:] in SUBMISSION_CACHE:
                    continue
                if log.created_utc <= time.time() - 3600:
                    break
                if r.redditor(log.target_author) in FRIEND_LIST:
                    consider_action("check_queue", r.submission(log.target_fullname[3:]))
                    SUBMISSION_CACHE[log.target_fullname[3:]] = log.created_utc
    except prawcore.exceptions.Forbidden as e:
        # probably removed from a subreddit
        logging.warning("exception checking queue: {}".format(e))
        # schedule load_subreddits in case check_mail does not run it
        schedule(load_subreddits, when="next")
        check_mail()
        schedule(check_mail, when="defer")
    except Exception as e:
        error = str(e)
        if error.startswith("<html>"):
            error = error.replace("\n", "")
        logging.error("exception checking queue: {}".format(error))


def check_accounts():
    logging.info("checking accounts")
    recent_activity = option(HOME, "recent_activity")
    if not isinstance(recent_activity, list) or not all(x and isinstance(x, dict) for x in recent_activity):
        return
    recent_activity_limit = option(HOME, "recent_activity_limit", 86400)
    if not isinstance(recent_activity_limit, int):
        return
    pause = time.time() + 60
    while NEW_FRIENDS and time.time() < pause:
        user = NEW_FRIENDS.pop(0)
        logging.info("scanning /u/{}".format(user))
        try:
            activity = 0
            posts = []
            for post in user.new(limit=100):
                activity += 1
                if member("moderated", post.subreddit) and post.created_utc > time.time() - recent_activity_limit:
                    posts.append(post)
            if not posts:
                continue
            age = (time.time() - user.created_utc) / 86400
            ban = set()
            entries = {}
            for post in posts:
                elapsed = int(time.time() - post.created_utc)
                hits = set()
                if post.fullname.startswith("t1_"):
                    post_type = "comment"
                elif post.fullname.startswith("t3_"):
                    post_type = "submission"
                else:
                    continue
                for limit in recent_activity:
                    matched = 0
                    matched += bool(limit.get("activity") and activity <= limit["activity"])
                    matched += bool(limit.get("age") and age <= limit["age"])
                    matched += bool(limit.get("elapsed") and elapsed <= limit["elapsed"])
                    matched += bool(limit.get("type") and post_type == limit["type"])
                    matched += bool(limit.get("banuser"))
                    if limit and matched == len(limit):
                        if post.subreddit not in entries:
                            entries[post.subreddit] = set()
                        entries[post.subreddit].add(post)
                        if limit.get("banuser"):
                            ban.add(post.subreddit)
            for subreddit, posts in entries.items():
                consider_action("check_accounts", posts, banuser=(subreddit in ban))
        except Exception as e:
            logging.warning("exception checking account /u/{}: {}".format(user, e))


def consider_action(caller, posts, banuser=True):
    global WHITELIST_CACHE

    if isinstance(posts, list):
        pass
    elif isinstance(posts, set):
        posts = sorted(posts, key=lambda x: x.created_utc, reverse=True)
    else:
        posts = [posts]

    account = posts[0].author
    subreddit = posts[0].subreddit

    if not member("moderated", subreddit):
        return False

    activity = (str(account), str(subreddit))
    if activity in WHITELIST_CACHE:
        return False

    # verify that all posts are matching
    if len(posts) > 1 and any(x.author != account or x.subreddit != subreddit for x in posts):
        logging.error(f"non-matching posts: {', '.join([x.fullname for x in posts])}")
        return False

    # all posts already handled
    if all(x.banned_by == ME for x in posts):
        return False

    logging.info(f"{caller} hit /u/{account} in /r/{subreddit}: {', '.join([x.fullname for x in posts])}")

    try:
        if re.search("proof\\b", str(posts[0].author_flair_css_class)):
            logging.info("/u/{} is whitelisted via flair class in /r/{}".format(account, subreddit))
            WHITELIST_CACHE[activity] = time.time()
            return False
    except Exception as e:
        logging.error("error checking flair class, failing safe for /u/{} in /r/{}: {}".format(account, subreddit, e))
        return False

    try:
        if any(x.distinguished for x in posts) or subreddit.moderator(account):
            logging.info("/u/{} is whitelisted via moderator list in /r/{}".format(account, subreddit))
            WHITELIST_CACHE[activity] = time.time()
            return False
    except Exception as e:
        # fail safe
        logging.error("error checking moderator list, failing safe for /u/{} in /r/{}: {}".format(account, subreddit, e))
        return False

    permissions = []
    try:
        permissions = subreddit.moderator(ME)[0].mod_permissions
        if not permissions:
            permissions.append("none")
    except Exception as e:
        logging.error("error checking moderator permissions in /r/{}: {}".format(subreddit, e))

    try:
        if (not permissions or "access" in permissions or "all" in permissions) and subreddit.subreddit_type != "user":
            for contributor in subreddit.contributor(account):
                logging.info("/u/{} is whitelisted via approved users in /r/{}".format(account, subreddit))
                WHITELIST_CACHE[activity] = time.time()
                return False
    except Exception as e:
        logging.error("error checking approved users, failing safe for /u/{} in /r/{}: {}".format(account, subreddit, e))
        return False

    if is_friend(account):
        logging.info("/u/{} confirmed to be on friends list".format(account))
    else:
        logging.warning("/u/{} is not on friends list".format(account))
        return False

    if banuser and ("access" in permissions or "all" in permissions):
        ban(account, subreddit, short_link(posts[0]), ("mail" in permissions))

    for post in posts:
        if getattr(post, "removed", None) or getattr(post, "spam", None):
            continue
        delay = int(time.time() - post.created_utc)
        link = short_link(post)
        if "posts" in permissions or "all" in permissions:
            try:
                logging.info("removing {} by /u/{} after {} seconds".format(link, account, delay))
                post.mod.remove(spam=True)
            except Exception as e:
                logging.error("error removing {}: {}".format(link, e))
        elif permissions:
            try:
                logging.info("reporting {} by /u/{} after {} seconds".format(link, account, delay))
                post.report(option(HOME, "report_reason"))
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
        if type(e) == praw.exceptions.RedditAPIException and e.items[0].error_type in ["NOT_FRIEND", "USER_DOESNT_EXIST"]:
            return False
        logging.warning("exception checking friends for /u/{}: {}".format(user, e))
    return None


def add_friend(user):
    global FRIEND_LIST

    user.friend()
    r.user.me().subreddit.flair.set(user, text="banned", css_class="banned")
    FRIEND_LIST.add(user)
    NEW_FRIENDS.append(user)
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
        message, message_log = option(HOME, "ban_message"), "default"
        note, note_log = option(HOME, "ban_note"), "default"
        for group in ["nsfw", "restricted"]:
            group_message = None
            group_note = None
            if member(group, subreddit):
                group_message = option(HOME, f"ban_message_{group}")
                group_note = option(HOME, f"ban_note_{group}")
            if group_message:
                message, message_log = group_message, group
            if group_note:
                note, note_log = group_note, group
        if isinstance(message, list):
            message = random.choice(message)
        if not isinstance(message, str):
            logging.error("ban message configuration error")
            message = "Bots and bot-like accounts are not welcome on /r/{subreddit}."
        if not isinstance(note, str):
            logging.error("ban note configuration error")
            note = "/u/{account} banned by /u/{me} at {date} for {reason}"
        message = message.format(subreddit=subreddit, home=HOME, account=account)
        note = note.format(account=account, me=ME, date=date, reason=link)
        subreddit.banned.add(account, ban_message=message, note=note)
        logging.info("banned /u/{} in /r/{} ({} message, {} note)".format(account, subreddit, message_log, note_log))
        if mail and option(subreddit, "modmail_mute"):
            logging.info("muting /u/{} in /r/{}".format(account, subreddit))
            subreddit.muted.add(account)
    except Exception as e:
        logging.error("error banning /u/{} in /r/{}: {}".format(account, subreddit, e))


def unban(account, subreddit, description=None):
    if isinstance(subreddit, str):
        subreddit = r.subreddit(subreddit)
    try:
        for ban in subreddit.banned(account):
            try:
                if ban.note and (ban.note == description or ME in ban.note):
                    logging.info("unbanning /u/{} on /r/{} ({})".format(account, subreddit, ban.note))
                    subreddit.banned.remove(account)
                else:
                    logging.debug("not unbanning /u/{} on /r/{} ({})".format(account, subreddit, ban.note or "[empty]"))
            except Exception as e:
                logging.error("exception unbanning /u/{} on /r/{}: {}".format(account, subreddit, e))
    except prawcore.exceptions.Forbidden as e:
        logging.debug("unable to check ban for /u/{} in /r/{}: {}".format(account, subreddit, e))
    except Exception as e:
        logging.warning("error checking ban for /u/{} in /r/{}: {}".format(account, subreddit, e))


def find_canonical(name, subreddit=None):
    title = "overview for " + name
    url = "https://www.reddit.com/user/" + name

    if not subreddit:
        subreddit = HOME

    try:
        for post in r.info(url=url):
            if post.title.lower() == title.lower() and post.author == ME and post.subreddit == subreddit and not post.removed_by_category:
                logging.info("using info result for {}".format(name))
                return post
    except Exception as e:
        logging.error("exception querying for canonical post: {}".format(e))

    try:
        for post in subreddit.search(f'title:"{name}"', limit=250):
            if post.title.lower() == title.lower() and post.author == ME:
                logging.info("using search result for {}".format(name))
                return post
    except Exception as e:
        logging.error("exception searching for canonical post: {}".format(e))

    try:
        for post in subreddit.new(limit=100):
            if post.title.lower() == title.lower() and post.author == ME:
                logging.info("using new result for {}".format(name))
                return post
    except Exception as e:
        logging.error("exception checking new for canonical post: {}".format(e))

    logging.info("no result for {}".format(name))
    return None


def account_name(submission):
    m = re.search(r'^https?://(?:\w+\.)?reddit\.com/u(?:ser)?/([\w-]{3,20})', str(submission.url))
    if m:
        return m.group(1)
    return None


def process_contribution(submission, result, note=None, reply=None, crosspost=None):
    global NOTE_FAILURE_CACHE

    note_post = None
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
            # multiple canonical check
            canonicals = set({crosspost.permalink})
            for post in duplicates:
                if post.subreddit == HOME and post.author == ME and not post.removed_by_category:
                    canonicals.add(post.permalink)
            if len(canonicals) > 1:
                logging.error("multiple canonical posts: {}".format(", ".join(sorted(canonicals))))
                schedule(check_duplicates, when="next")
                try:
                    for post in [crosspost] + list(duplicates):
                        if post.permalink in canonicals:
                            logging.info("saving duplicate {}".format(post.permalink))
                            post.save()
                except Exception as e:
                    logging.error("exception saving duplicates: {}".format(e))
            # make notes crosspost if needed
            notes = option(HOME, "notes")
            if notes:
                subreddit = r.subreddit(notes)
                # see if a notes post already exists
                for post in duplicates:
                    if post.subreddit == subreddit and not post.removed_by_category and not post.archived and post.title == crosspost.title and post.author == ME:
                        note_post = post
                if not note_post:
                    new = None
                    # submissions from private subreddits cannot be crossposted
                    if crosspost.subreddit.subreddit_type == "private":
                        new = subreddit.submit(crosspost.title, url=submission.url, send_replies=False)
                    else:
                        new = crosspost.crosspost(subreddit, send_replies=False)
                    if new:
                        account = account_name(crosspost)
                        if account in NOTE_FAILURE_CACHE:
                            del NOTE_FAILURE_CACHE[account]
                        note_post = new
    except Exception as e:
        logging.warning("exception crossposting {}: {}".format(crosspost.permalink, e))
    note = " " + note if note else ""
    log = "contribution {} from /u/{} with flair {} {}{}".format(submission.permalink, submission.author, submission.link_flair_text, result, note)
    if result == "error":
        logging.error(log)
        HOME.message(subject="Error processing contribution", message="{}".format(submission.permalink))
    else:
        logging.info(log)
    return note_post


def check_contributions():
    global CONTRIBUTION_LIMIT

    logging.info("checking for contributions")

    # process oldest submissions first
    submissions = []
    moderators = []
    try:
        # check submissions
        newest = None
        for submission in r.multireddit(redditor=ME, name="contributions").new(limit=1000):
            if newest is None:
                newest = submission
            if submission.created_utc < CONTRIBUTION_LIMIT or submission.created_utc < time.time() - 86400:
                break
            if submission.author != ME:
                # fetch moderator list once
                if not moderators:
                    moderators = list(map(str, HOME.moderator()))
                # allow time for submission statement
                if submission.author in moderators or submission.created_utc < time.time() - 60 or (submission.num_comments and len(submission.comments)):
                    submissions.insert(0, submission)
        # set future limit
        if submissions:
            CONTRIBUTION_LIMIT = submissions[0].created_utc - 600
        elif newest:
            CONTRIBUTION_LIMIT = newest.created_utc - 3600
    except Exception as e:
        logging.error("exception checking submissions: {}".format(e))

    # fetch templates once
    templates = None

    # process submissions for a limited period of time
    pause = time.time() + 60
    for submission in submissions:
        if time.time() >= pause:
            break

        if submission.author in FRIEND_LIST:
            logging.info("contribution from friend /u/{}".format(submission.author))
            if consider_action("check_contributions", submission):
                continue

        # require account
        account = account_name(submission)
        if not account:
            continue

        # set flair if AutoModerator failed
        try:
            if not submission.link_flair_text and submission.created_utc < time.time() - 600:
                flair = None
                if templates is None:
                    templates = list(HOME.flair.link_templates)
                for template in templates:
                    if template.get("css_class") == "contribution":
                        flair = template.get("id")
                        break
                logging.warning("setting flair for contribution {}".format(submission.permalink))
                if flair:
                    submission.mod.flair(flair_template_id=flair)
                else:
                    submission.mod.flair(text="contribution", css_class="contribution")
                continue
        except Exception as e:
            logging.error("exception setting flair: {}".format(e))

        # wait for flair unless exempted
        if not (submission.link_flair_text or submission.author in moderators or submission.subreddit.subreddit_type == "private"):
            continue

        blocked = None
        name = None
        try:
            user = r.redditor(account)
            if getattr(user, "is_employee", None):
                blocked = ("admin", "an admin", "an admin")
            elif user in moderators:
                blocked = ("moderator", "a moderator", "a moderator")
            elif user == submission.author:
                blocked = ("submitter", "your own", "their own")
            name = user.name
        except Exception as e:
            logging.debug("exception checking account {}: {}".format(account, e))

        if not name or getattr(user, "is_suspended", None):
            reply = ("Thank you for your submission! That account does not appear to exist"
                     " (perhaps it has already been suspended, banned, or deleted), but"
                     " please message /r/{} if you believe this was an error.".format(HOME))
            process_contribution(submission, "rejected", reply=reply)
            continue

        if blocked:
            process_contribution(submission, "blocked", note=f"({blocked[0]} account)")
            if submission.author not in moderators:
                HOME.banned.add(submission.author,
                                ban_message=f"Submitting {blocked[1]} account is not allowed.",
                                note=f"submitted {blocked[2]} account {submission.permalink}")
            continue

        approved = True
        try:
            if submission.num_reports:
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
        report_type = "Reviewable"
        report_text = None
        try:
            if approved and not canonical:
                css_class = "pending"
                if submission.link_flair_text:
                    m = re.search("^contribution-(\w+)$", submission.link_flair_text)
                    if m:
                        # assign flair for moderators and flaired users providing a submission statement
                        assign_flair = submission.author in moderators
                        if not assign_flair and submission.num_comments and len(submission.comments) and submission.comments[0].author == submission.author:
                            user_flair = next(submission.subreddit.flair(submission.author))
                            if user_flair.get("user") == submission.author and user_flair.get("flair_css_class"):
                                assign_flair = True
                        if assign_flair:
                            css_class = m.group(1)
                            report_type = css_class.capitalize()
                flair = None
                try:
                    if templates is None:
                        templates = list(HOME.flair.link_templates)
                    for template in templates:
                        if template.get("css_class") == css_class:
                            flair = template.get("id")
                            break
                except Exception as e:
                    logging.warning("exception searching link templates: {}".format(e))
                title = "overview for " + name
                url = "https://www.reddit.com/user/" + name
                post = HOME.submit(title, url=url, send_replies=False, flair_id=flair)
                report_text = "{} submission from /u/{}".format(report_type, submission.author)
        except Exception as e:
            logging.error("exception creating canonical post: {}".format(e))

        if post:
            reply = ("Thank you for your submission! We have created a new"
                     " [entry for this account]({}).".format(post.permalink))
            note_post = process_contribution(submission, "accepted", note="for {}".format(name), reply=reply, crosspost=post)
            if report_text and note_post:
                report_text += f" (https://redd.it/{note_post.id})"
            for attempt in range(3):
                try:
                    post.report(report_text)
                    if report_type != "Reviewable":
                        sync_submission(post)
                        post.mod.approve()
                    break
                except Exception as e:
                    logging.error("exception reporting canonical post: {}".format(e))
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
    global NOTE_UNLOCKED_CACHE

    logging.info("checking for notes")
    notes = option(HOME, "notes")
    if not notes:
        return

    # find locked comments
    locked = {}
    comments = []
    try:
        for log in r.get(path=f"/user/{ME}/m/contributions/about/log/", params={"limit": 500, "type": "lock"}):
            if log.created_utc < time.time() - 28800:
                break
            if log.created_utc > time.time() - 180 or log.target_author == ME:
                continue
            if not log.target_fullname or not log.target_fullname.startswith("t1_"):
                continue
            # comments to process
            if log.created_utc > NOTE_UNLOCKED_CACHE.get(log.target_fullname, 0):
                locked[log.target_fullname] = max(log.created_utc, locked.get(log.target_fullname, 0))
        for comment in r.info(fullnames=locked.keys()):
            if comment.locked:
                # failure cases
                failure = None
                last_update = max(comment.created_utc, comment.edited or 0)
                if last_update < time.time() - 21600:
                    failure = "persistent failure"
                elif comment.body == "[deleted]":
                    failure = "deleted comment"
                if failure:
                    logging.warning(f"unable to create note for {comment.permalink} ({failure})")
                    comment.mod.unlock()
                    if comment.fullname in locked:
                        NOTE_UNLOCKED_CACHE[comment.fullname] = locked[comment.fullname]
                # process recent comments
                else:
                    comments.insert(0, comment)
            elif comment.fullname in locked:
                NOTE_UNLOCKED_CACHE[comment.fullname] = locked[comment.fullname]
        if locked or comments:
            logging.info(f"{len(locked)} locked targets, {len(comments)} locked comments")
        if not comments:
            return
    except Exception as e:
        logging.error("exception checking comments: {}".format(e))

    # populate submissions
    try:
        submissions = {}
        for info in r.info(fullnames=set(map(lambda x: x.link_id, comments))):
            submissions[info.fullname] = info
        for comment in comments:
            if submissions.get(comment.link_id):
                comment.submission = submissions[comment.link_id]
    except Exception as e:
        logging.error("exception populating submissions: {}".format(e))

    # process comments for a limited period of time
    pause = time.time() + 60
    skipped = set()
    # process oldest comments first
    for comment in sorted(comments, key=lambda x: int(x.id, 36)):
        if time.time() >= pause:
            break

        try:
            account = account_name(comment.submission)
            if not account:
                comment.mod.unlock()
                if comment.fullname in locked:
                    NOTE_UNLOCKED_CACHE[comment.fullname] = locked[comment.fullname]
                continue

            # comment made directly on notes post
            if comment.submission.author == ME and comment.subreddit == notes and not comment.submission.removed_by_category:
                comment.mod.unlock()
                if comment.fullname in locked:
                    NOTE_UNLOCKED_CACHE[comment.fullname] = locked[comment.fullname]
                continue

            # skip recent failures
            if account in NOTE_FAILURE_CACHE:
                skipped.add(comment.id)
                continue

            # find notes post
            post = find_canonical(account, subreddit=r.subreddit(notes))

            # skip comment if missing
            if not post:
                NOTE_FAILURE_CACHE[account] = time.time()
                logging.warning("unable to find notes post for {}".format(comment.permalink))
                continue

            # process note
            attribution = "Note from /u/{} at {}".format(comment.author, comment.permalink)
            try:
                text = "{}:\n\n---\n\n{}".format(attribution, comment.body)
                edit = None
                existing_text = set()
                try:
                    if comment.edited and post.num_comments:
                        for existing in post.comments.list():
                            if existing.author != ME or not existing.body.startswith(attribution):
                                continue
                            if not edit or existing.created_utc > edit.created_utc:
                                edit = existing
                            existing_text.add(hash(existing.body))
                except Exception as e:
                    logging.warning("exception checking notes on {}: {}".format(post.permalink, e))
                if hash(text) not in existing_text:
                    if edit and len(text) > len(edit.body) / 2:
                        logging.info("editing note for {} at {}".format(comment.permalink, edit.permalink))
                        edit.edit(body=text)
                    else:
                        logging.info("creating note for {} on {}".format(comment.permalink, post.permalink))
                        post.reply(body=text)
                comment.mod.unlock()
                if comment.fullname in locked:
                    NOTE_UNLOCKED_CACHE[comment.fullname] = locked[comment.fullname]
            except praw.exceptions.RedditAPIException as e:
                logging.warning("exception creating note for {}, trying again with short note: {}".format(comment.permalink, e))
                try:
                    text = "{}.".format(attribution)
                    if hash(text) not in existing_text:
                        post.reply(body=text)
                    comment.mod.unlock()
                    if comment.fullname in locked:
                        NOTE_UNLOCKED_CACHE[comment.fullname] = locked[comment.fullname]
                except Exception as e:
                    logging.error("exception creating note for {}: {}".format(comment.permalink, e))
            except Exception as e:
                logging.error("exception creating note for {}: {}".format(comment.permalink, e))
        except Exception as e:
            logging.error("exception checking for notes: {}".format(e))

    if skipped:
        logging.info("skipped due to recent failure: {}".format(", ".join(sorted(skipped))))


def check_duplicates():
    logging.info("checking for duplicates")
    try:
        # find duplicates
        urls = {}
        for iterator in HOME.new(limit=1000), HOME.search(f'author:{ME}', limit=250, sort='new'), r.user.me().saved(limit=1000):
            for post in iterator:
                if post.author == ME and post.url and post.url.startswith("https://www.reddit.com/user/"):
                    urls[post.url] = set.union(urls.get(post.url, set()), set([post.fullname]))
                if post.saved:
                    post.unsave()
        references = None
        for url, fullnames in urls.items():
            if len(fullnames) == 1:
                continue
            item = "multiple canonical posts for {} ({})".format(url, ", ".join(sorted(fullnames)))
            logging.warning(item)
            # count recent references to canonical posts
            if references is None:
                references = {}
                for comment in r.redditor(ME).comments.new(limit=1000):
                    for match in re.findall(f'/r/{HOME}/comments/\w+/\w+/', comment.body):
                        references[match] = set.union(references.get(match, set()), set([comment.id]))
            # score each canonical post
            posts = sorted(r.info(fullnames=fullnames), key=lambda x: int(x.id, 36), reverse=True)
            scores = {}
            for post in posts:
                first = 1 if not scores else 0
                scores[post.fullname] = 10 * abs(post.num_reports) + len(references.get(post.permalink, set())) + first / 10
            keep = sorted(fullnames, key=lambda x: scores.get(x, 0), reverse=True)[0]
            if keep:
                for post in posts:
                    keep_string = "keeping" if keep == post.fullname else "removing"
                    subitem = "{} duplicate {} for {}".format(keep_string, post.permalink, post.url)
                    logging.info(subitem)
                    if keep != post.fullname:
                        post.mod.remove()
    except Exception as e:
        logging.error("exception checking for duplicate posts: {}".format(e))


def check_mail():
    logging.info("checking mail")
    try:
        # private messages
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
                message.mark_read()
                continue

            # handle non-subreddit messages
            if not message.subreddit:
                message.mark_read()
                if message.distinguished == "admin":
                    # added as moderator by admin
                    if re.search("\\byou are a moderator\\b", str(message.subject), re.I):
                        m = re.search("\\badded as a moderator to\W+?(/?(r|u|user)/[\w-]+)", str(message.body))
                        if m:
                            logging.info("added to {} by /u/{}".format(m.group(1), message.author))
                        schedule(load_subreddits, when="next")
                    continue
                if message.distinguished == "gold-auto":
                    continue
                if message.author in ["[deleted]", "mod_mailer"]:
                    continue
                if message.author in FRIEND_LIST or message.author.moderated():
                    message.reply(body="I am a bot. If this is regarding {}, please message /r/{}. For anything else, please message the relevant subreddit.".format(ME, HOME))
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
                            permissions_string = ", ".join(permissions)
                            logging.info("incorrect permissions ({}) on /r/{}".format(permissions_string, subreddit))
                            reply = option(HOME, "permissions_message")
                            if reply:
                                message.reply(body=reply.format(me=ME, permissions=permissions_string, home=HOME))
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
                        message.reply(body=
                            "This bot isn't really needed on non-public subreddits due to very limited bot"
                            " activity. If you believe this was sent in error, please message /r/{}.".format(HOME)
                        )
            # looks like a removal
            elif re.search("^/?u/[\w-]+ has been removed as a moderator from /?(r|u|user)/[\w:-]+$", str(message.subject)):
                message.mark_read()
                load_subreddits()
                schedule(load_subreddits, when="defer")
                if not member("moderated", subreddit):
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
                canonical = find_canonical(str(account))
                if canonical and canonical.link_flair_text:
                    logging.info("creating note about /u/{} on /r/{}".format(account, thread.owner))
                    note = option(HOME, "note_home").format(account=account, classification=canonical.link_flair_text, link=canonical.permalink)
                    try:
                        mod_reports = canonical.mod_reports_dismissed + canonical.mod_reports
                    except AttributeError:
                        mod_reports = canonical.mod_reports
                    notes = []
                    for report, moderator in mod_reports:
                        if moderator == ME:
                            contributor = ""
                            m = re.search("\\bsubmission (?:\S+ )?from (/u/[\w-]{3,20})", report)
                            if m:
                                contributor = "from {} ".format(m.group(1))
                            created = absolute_time(canonical.created_utc)
                            notes.insert(0, "- Submission {}posted {}".format(contributor, created))
                        elif not re.search("^(ignore|show|test)\\b.{0,16}$", report, re.I):
                            notes.append("- {}: {}".format(moderator, report))
                    for post in set(canonical.duplicates()):
                        if post.author != ME:
                            continue
                        if post.subreddit != option(HOME, "notes"):
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
                                thread.reply(body=option(HOME, "appeal_message").format(home=HOME), author_hidden=True)
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
            canonical = find_canonical(str(account))
            if canonical:
                reply = option(HOME, "note_other")
                if reply:
                    logging.info("creating note about /u/{} on /r/{}".format(account, thread.owner))
                    thread.reply(body=reply.format(account=account, home=HOME, link=canonical.permalink, subreddit=thread.owner), internal=True)
    except Exception as e:
        logging.error("exception checking modmail {}: {}".format(thread, e))

    # trim cache
    if len(MODMAIL_IDS) > 200:
        MODMAIL_IDS = MODMAIL_IDS[-200:]


def join_subreddit(subreddit):
    try:
        if subreddit.quarantine:
            return False, "quarantined"
        elif subreddit.subreddit_type not in ["public", "restricted", "gold_only", "user"]:
            return False, subreddit.subreddit_type
        elif member("prohibited", subreddit):
            HOME.message(subject="Invitation from prohibited subreddit", message="/r/{}".format(subreddit))
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
        SUBREDDITS["moderated"].add(str(subreddit))
        try:
            if subreddit.over18:
                SUBREDDITS["nsfw"].add(str(subreddit))
            if member("restricted", subreddit):
                HOME.message(subject="Joined restricted subreddit", message="/r/{}".format(subreddit))
        except Exception as e:
            logging.error("exception after joining /r/{}: {}".format(subreddit, e))
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
    global NOTE_FAILURE_CACHE
    global NOTE_UNLOCKED_CACHE
    global SUBMISSION_CACHE
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
                if submission.removed_by_category:
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
                    subreddits = list(map(str, r.user.me().moderated()))
                    if not subreddits:
                        raise RuntimeError("empty subreddit list")
                    canonical = find_canonical(str(flair["user"]))
                    UNBAN_STATE[(flair["user"], canonical.created_utc if canonical else 0)] = subreddits
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
    expire_cache(NOTE_UNLOCKED_CACHE, 28800)
    expire_cache(SUBMISSION_CACHE, 3600)
    expire_cache(WHITELIST_CACHE, 86400)


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
                HOME.message(subject="Error adding inactive", message="/u/{}".format(user))
            return
        # neither banned nor inactive
        elif user in FRIEND_LIST or user in INACTIVE_LIST:
            try:
                if user in FRIEND_LIST:
                    remove_friend(user)
                    logging.info("removed friend /u/{}".format(user))
            except Exception as e:
                logging.error("error removing friend /u/{}: {}".format(user, e))
                HOME.message(subject="Error removing friend", message="/u/{}".format(user))
            try:
                if user in INACTIVE_LIST:
                    remove_inactive(user)
                    logging.info("removed inactive /u/{}".format(user))
            except Exception as e:
                logging.error("error removing inactive /u/{}: {}".format(user, e))
                HOME.message(subject="Error removing inactive", message="/u/{}".format(user))
            try:
                if submission.link_flair_text in ["declined", "organic", "service"]:
                    HOME.flair.set(user, css_class="unban")
            except Exception as e:
                logging.error("error adding unban /u/{}: {}".format(user, e))
                HOME.message(subject="Error adding unban", message="/u/{}".format(user))


def check_unbans():
    logging.info("checking unbans")
    if not UNBAN_STATE:
        return
    try:
        current = next(iter(UNBAN_STATE))
        account, submitted = current
        logging.info("processing unban for /u/{} ({} subreddits remaining)".format(account, len(UNBAN_STATE[current])))
        # fast method
        try:
            if UNBAN_STATE[current] and submitted > time.time() - 7776000:
                query = random_subreddits(UNBAN_STATE[current])
                done = set()
                for log in r.subreddit(query).mod.log(action="banuser", mod=ME, limit=None):
                    if log.mod == ME and log.target_author == account and log.subreddit not in done:
                        unban(account, log.subreddit, description=log.description)
                        done.add(log.subreddit)
                    if log.created_utc < submitted:
                        break
                for subreddit in query.split("+"):
                    UNBAN_STATE[current].remove(subreddit)
                if UNBAN_STATE[current]:
                    return
        except Exception as e:
            logging.error("exception checking logs: {}".format(e))
        # slow method
        pause = time.time() + 10
        while UNBAN_STATE[current] and time.time() < pause:
            unban(account, UNBAN_STATE[current].pop(0))
        # delete if finished
        if not UNBAN_STATE[current]:
            logging.info("finished unban for /u/{}".format(account))
            HOME.flair.delete(account)
            del UNBAN_STATE[current]
            if not UNBAN_STATE:
                schedule(check_unbans, schedule=86400, when="defer")
    except Exception as e:
        logging.error("exception checking unbans: {}".format(e))


if __name__ == "__main__":
    SCHEDULE = {
        check_accounts: 120,
        check_comments: 5,
        check_contributions: 60,
        check_duplicates: 3600,
        check_mail: 120,
        check_modmail: 30,
        check_notes: 120,
        check_queue: 20,
        check_state: 300,
        check_submissions: 30,
        check_unbans: 86400,
        kill_switch: 120,
        load_configuration: 3600,
        load_flair: 86400,
        load_subreddits: 86400,
        update_status: 900,
    }
    NEXT = SCHEDULE.copy()

    try:
        logging.info("starting")
        schedule(kill_switch, when="next")
        schedule(load_configuration, when="next")
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

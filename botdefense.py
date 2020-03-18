#!/usr/bin/python

import praw
import prawcore.exceptions
import time
from datetime import datetime
import re
import logging


# global data
STATUS_POST = None
SUBREDDIT_LIST = []
COMMENT_IDS = []
SUBMISSION_IDS = []
QUEUE_IDS = []
LOG_IDS = []
FREQUENCY = {
    "kill_switch": 60,
    "update_status": 300,
    "load_subreddits": 3600,
    "check_comments": 5,
    "check_submissions": 30,
    "check_queue": 60,
    "check_mail": 120,
    "check_contributions": 60,
    "check_unbans": 15,
    "sync_friends": 300,
}
LAST = {}
BAN_MESSAGE = ("Bots are not welcome on /r/{}.\n\n"
               "[I am a bot, and this action was performed automatically]"
               "(/r/BotDefense/about/sticky). "
               "If you wish to dispute whether this account is a bot, please "
               "[contact the moderators of /r/BotDefense]"
               "(https://www.reddit.com/message/compose?"
               "to=/r/BotDefense&subject=Ban%20dispute%20for%20/u/{}%20on%20/r/{}).")
PERMISSIONS_MESSAGE = ("Thank you for adding BotDefense!\n\n"
                       "This bot works best with `access` and `posts` permissions (current permissions: {}). "
                       "For more information, [please read this guide](/r/BotDefense/about/sticky).")
UNBAN_STATE = {}

# setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(funcName)s | %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
)
praw_config = {"user_agent": "linux:botdefense:v1.0 (by /u/BotDefense)"}
r = praw.Reddit("botdefense", **praw_config)


def ready(key, force=False):
    global LAST

    if force or LAST.get(key, 0) < time.time() - FREQUENCY.get(key, 60):
        LAST[key] = time.time()
        return 1
    return 0


def kill_switch():
    if not ready("kill_switch"):
        return

    logging.info("checking kill switch")
    active = False
    while not active:
        try:
            if r.subreddit("BotDefense").moderator("BotDefense")[0].mod_permissions:
                active = True
        except Exception as e:
            logging.error("exception checking permissions: {}".format(e))
        if not active:
            logging.info("kill switch activated, sleeping")
            # sleep needs to be before any other actions to reduce the odds of spinning
            time.sleep(60)


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

    if not ready("update_status"):
        return

    logging.info("updating status")
    if not STATUS_POST:
        for result in r.subreddit("BotDefense").search('title:"BotDefense status"', sort='new'):
            if result.author == "BotDefense" and result.is_self:
                STATUS_POST = result
                break
        if not STATUS_POST:
            logging.error("unable to locate status post")
            return

    last_time = None
    last_type = None
    recent_logs = ""
    try:
        current_time = absolute_time(time.time())
        for log in r.subreddit("mod").mod.log(mod="BotDefense", limit=500):
            if not last_time:
                last_time = absolute_time(log.created_utc)
                last_type = log.action
            if log.created_utc < time.time() - 86400:
                break
            if log.action in ["banuser", "spamcomment"]:
                recent_logs += "|{}|{}|/u/{}|\n".format(relative_time(log.created_utc), log.action, log.target_author)

        if recent_logs:
            recent_logs = "|Time|Action|Account|\n|-|-|-|\n" + recent_logs
        STATUS_POST.edit("|Attribute|Value|\n"
                         "|-|-|\n"
                         "|Current time|{}|\n"
                         "|Last action time|{}|\n"
                         "|Last action type|{}|\n"
                         "\n&nbsp;\n&nbsp;\n\n{}"
                         .format(current_time,
                                 last_time,
                                 last_type,
                                 recent_logs))
    except Exception as e:
        logging.error("unable to update status: {}".format(e))


def load_subreddits(force=False):
    global SUBREDDIT_LIST

    if not ready("load_subreddits", force=force):
        return

    logging.info("loading subreddits")
    SUBREDDIT_LIST = []
    # use this method to avoid 100 subreddit limit for now
    mod_target = "/user/" + str(r.user.me()) + "/moderated_subreddits"
    for subreddit in r.get(mod_target)['data']:
        name = subreddit['sr']
        SUBREDDIT_LIST.append(r.subreddit(name).display_name)


def check_comments():
    global COMMENT_IDS

    if not ready("check_comments"):
        return

    logging.info("checking comments")
    for comment in r.subreddit("friends").comments(limit=100):
        if str(comment.id) in COMMENT_IDS:
            continue
        link = "https://www.reddit.com/comments/{}/_/{}".format(comment.submission.id, comment.id)
        consider_action(comment, link)
        # we only cache identifiers after processing successfully
        COMMENT_IDS.append(str(comment.id))

    # trim cache
    if len(COMMENT_IDS) > 200:
        COMMENT_IDS = COMMENT_IDS[100:]


def check_submissions():
    global SUBMISSION_IDS

    if not ready("check_submissions"):
        return

    logging.info("checking submissions")
    for submission in r.subreddit("friends").new(limit=100):
        if str(submission.id) in SUBMISSION_IDS:
            continue
        link = "https://www.reddit.com/comments/" + str(submission.id)
        consider_action(submission, link)
        # we only cache identifiers after processing successfully
        SUBMISSION_IDS.append(str(submission.id))

    # trim cache
    if len(SUBMISSION_IDS) > 200:
        SUBMISSION_IDS = SUBMISSION_IDS[100:]


def check_queue():
    global QUEUE_IDS

    if not ready("check_queue"):
        return

    logging.info("checking queue")
    friends = []
    for submission in r.subreddit("mod").mod.modqueue(limit=100, only="submissions"):
        if str(submission.id) in QUEUE_IDS:
            continue
        if not friends:
            friends = r.user.friends()
        if submission.author in friends:
            link = "https://www.reddit.com/comments/" + str(submission.id)
            logging.info("queue hit for /u/{} in /r/{} at {}".format(submission.author, submission.subreddit, link))
            consider_action(submission, link)
        # we only cache identifiers after processing successfully
        QUEUE_IDS.append(str(submission.id))

    # trim cache
    if len(QUEUE_IDS) > 200:
        QUEUE_IDS = QUEUE_IDS[100:]


def consider_action(post, link):
    sub = str(post.subreddit)
    author = str(post.author)

    if sub not in SUBREDDIT_LIST:
        return

    logging.info("subreddit hit /u/{} in /r/{}".format(author, sub))
    permissions = []
    try:
        permissions = post.subreddit.moderator("BotDefense")[0].mod_permissions
    except Exception as e:
        logging.error("error checking moderator permissions in /r/{}: {}".format(sub, e))

    is_friended = False
    if is_friend(author):
        is_friended = True
        logging.info("/u/{} confirmed to be on friends list".format(author))
    else:
        logging.error("/u/{} is not on friends list".format(author))

    is_proof_flaired = False
    try:
        if re.search("proof\\b", str(post.author_flair_css_class)):
            is_proof_flaired = True
            logging.info("/u/{} is whitelisted via flair class in /r/{}".format(author, sub))
    except Exception as e:
        logging.error("error checking flair class for /u/{} in /r/{}: {}".format(author, sub, e))

    is_contributor = False
    try:
        for contributor in post.subreddit.contributor(author):
            is_contributor = True
            logging.info("/u/{} is whitelisted via approved users in /r/{}".format(author, sub))
    except Exception as e:
        logging.info("unable to check approved users for /u/{} in /r/{}: {}".format(author, sub, e))
        # fail safe
        if not permissions or "access" in permissions or "all" in permissions:
            is_contributor = True
            logging.error("failing safe for /u/{} in /r/{}".format(author, sub))

    is_moderator = False
    try:
        if post.subreddit.moderator(author):
            is_moderator = True
            logging.info("/u/{} is whitelisted via moderator list in /r/{}".format(author, sub))
    except Exception as e:
        # fail safe
        is_moderator = True
        logging.error("error checking moderator list, failing safe for /u/{} in /r/{}: {}".format(author, sub, e))

    if is_friended and not is_proof_flaired and not is_contributor and not is_moderator:
        if "access" in permissions or "all" in permissions:
            ban(author, sub, link, ("mail" in permissions))
        if "posts" in permissions or "all" in permissions:
            try:
                if not (post.removed or post.spam):
                    logging.info("removing " + link)
                    post.mod.remove(spam=True)
            except Exception as e:
                logging.error("error removing {}: {}".format(link, e))
        elif permissions:
            try:
                post.report("bot (moderator permissions limited to reporting)")
            except Exception as e:
                logging.error("error reporting {}: {}".format(link, e))


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


def ban(author, sub, link, mute):
    already_banned = False
    logging.info("banning /u/{} in /r/{}".format(author, sub))
    try:
        for ban in r.subreddit(sub).banned(author):
            logging.info("/u/{} already banned in /r/{}".format(author, sub))
            already_banned = True
    except Exception as e:
        logging.error("error checking ban status for /u/{} in /r/{}: {}".format(author, sub, e))
    if not already_banned:
        date = str(datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d"))
        try:
            r.subreddit(sub).banned.add(
                author, ban_message=BAN_MESSAGE.format(sub, author, sub),
                note="/u/{} banned by /u/BotDefense at {} for {}".format(author, date, link))
            logging.info("banned /u/{} in /r/{}".format(author, sub))
            if mute:
                logging.info("muting /u/{} in /r/{}".format(author, sub))
                r.subreddit(sub).muted.add(author)
        except Exception as e:
            logging.error("error banning /u/{} in /r/{}: {}".format(author, sub, e))


def unban(account, subreddit):
    try:
        for ban in r.subreddit(subreddit).banned(account):
            try:
                if ban.note and re.search("BotDefense", ban.note):
                    logging.info("unbanning /u/{} on /r/{} ({})".format(account, subreddit, ban.note))
                    r.subreddit(subreddit).banned.remove(account)
                else:
                    logging.debug("not unbanning /u/{} on /r/{} ({})".format(account, subreddit, ban.note or "[empty]"))
            except Exception as e:
                logging.error("exception unbanning /u/{} on /r/{}".format(account, subreddit))
    except prawcore.exceptions.Forbidden as e:
        logging.info("unable to check ban for /u/{} in /r/{}: {}".format(account, subreddit, e))
    except Exception as e:
        logging.warning("error checking ban for /u/{} in /r/{}: {}".format(account, subreddit, e))


def check_contributions():
    if not ready("check_contributions"):
        return

    logging.info("checking for contributions")
    for submission in r.subreddit("BotDefense").new(limit=100):
        if submission.author == "BotDefense":
            continue

        account = None
        name = None
        canonical = None
        post = None

        if submission.url:
            m = re.search("^https?://(?:\w+\.)?reddit\.com/(?:u|user)/([\w-]{3,20})", submission.url)
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
            comment = submission.reply("Thank you for your submission! That account does not appear to"
                                       " exist (perhaps it has already been suspended, banned, or deleted),"
                                       " but please send modmail if you believe this was an error.")
            comment.mod.distinguish()
            logging.info("contribution {} rejected".format(submission.permalink))
            continue

        title = "overview for " + name
        url = "https://www.reddit.com/user/" + name

        for query in "url:\"{}\"".format(url), "title:\"{}\"".format(name):
            try:
                for similar in r.subreddit("BotDefense").search(query):
                    if similar.title == title and similar.author == "BotDefense":
                        canonical = similar
                        break
                if canonical:
                    break
            except Exception as e:
                logging.error("exception searching {} for canonical post: {}".format(query, e))

        try:
            if not canonical:
                for recent in r.subreddit("BotDefense").new(limit=1000):
                    if recent.title == title and recent.author == "BotDefense":
                        canonical = recent
                        break
        except Exception as e:
            logging.error("exception checking recent posts for canonical post: {}".format(e))

        try:
            if not canonical:
                post = r.subreddit("BotDefense").submit(title, url=url)
                post.report("Reviewable submission from /u/{}: please approve and update flair".format(submission.author))
                post.disable_inbox_replies()
        except Exception as e:
            logging.error("exception creating canonical post: {}".format(e))

        submission.mod.remove()
        if post:
            comment = submission.reply("Thank you for your submission! We have created a new"
                                       " [entry for this account]({}).".format(post.permalink))
            comment.mod.distinguish()
            logging.info("contribution {} accepted for {}".format(submission.permalink, name))
        elif canonical:
            comment = submission.reply("Thank you for your submission! It looks like we already have"
                                       " an [entry for this account]({}).".format(canonical.permalink))
            comment.mod.distinguish()
            logging.info("contribution {} duplicate for {}".format(submission.permalink, name))
        else:
            comment = submission.reply("Thank you for your submission!")
            comment.mod.distinguish()
            logging.error("contribution {} error".format(submission.permalink))
            r.subreddit("BotDefense").message("Error processing contribution",
                                              "{}".format(submission.permalink))


def check_mail():
    if not ready("check_mail"):
        return

    logging.info("checking mail")
    for message in r.inbox.unread(limit=10):
        try:
            # skip non-messages and some accounts
            if not message.fullname.startswith("t4_") or message.author in ["mod_mailer", "reddit"]:
                message.mark_read()
                continue
            # skip non-subreddit messages
            if not message.subreddit:
                message.mark_read()
                if message.distinguished != "admin":
                    message.reply("Please modmail /r/BotDefense if you would like to get in touch.")
                continue

            sub = message.subreddit.display_name

            # looks like an invite
            if re.search("^invitation to moderate /?(r|u|user)/[\w-]+$", str(message.subject)):
                logging.info("invited to moderate /r/{}".format(sub))
                result = None
                reason = None

                try:
                    result, reason = join_subreddit(message.subreddit)
                except:
                    reason = "error"

                if result:
                    message.mark_read()
                    logging.info("joined /r/{}".format(sub))
                    permissions = message.subreddit.moderator("BotDefense")[0].mod_permissions
                    if not "all" in permissions:
                        if not "access" in permissions or not "posts" in permissions:
                            if not permissions:
                                permissions = ["*no permissions*"]
                            logging.warning("incorrect permissions ({}) on /r/{}".format(", ".join(permissions), sub))
                            message.reply(PERMISSIONS_MESSAGE.format(", ".join(permissions)))
                else:
                    message.mark_read()
                    if reason == "error":
                        logging.info("failure accepting invite {} from /r/{}".format(message.fullname, sub))
                    elif reason:
                        logging.info("declining invite from {} subreddit /r/{}".format(reason, sub))
                        message.reply(
                            "This bot isn't really needed on non-public subreddits due to very limited bot"
                            " activity. If you believe this was sent in error, please modmail /r/BotDefense."
                        )
            # looks like a removal
            elif re.search("^/?u/[\w-]+ has been removed as a moderator from /?(r|u|user)/[\w-]+$", str(message.subject)):
                message.mark_read()
                load_subreddits(force=True)
                if sub not in SUBREDDIT_LIST:
                    logging.info("removed as moderator from /r/" + sub)
            # some other type of subreddit message
            else:
                message.mark_read()
        except Exception as e:
            logging.error("exception checking mail: {}".format(e))


def join_subreddit(subreddit):
    if subreddit.quarantine:
        return False, "quarantined"
    elif subreddit.subreddit_type not in ["public", "restricted", "gold_only", "user"]:
        return False, subreddit.subreddit_type

    try:
        subreddit.mod.accept_invite()
        SUBREDDIT_LIST.append(subreddit.display_name)
    except Exception as e:
        logging.error("exception joining /r/{}: {}".format(subreddit.display_name, e))
        return False, "error"
    else:
        return True, None


def sync_friends():
    global LOG_IDS

    if not ready("sync_friends"):
        return

    logging.info("syncing friends")
    try:
        friends = []
        recent = {}
        for log in r.subreddit("BotDefense").mod.log(action="editflair", limit=100):
            # only log ids can be persistently cached, not submission ids
            if str(log.id) in LOG_IDS:
                continue
            # cache friends and recent submissions
            if not friends:
                friends = r.user.friends()
                if not friends:
                    raise ValueError("empty friends list")
                for submission in r.subreddit("BotDefense").new(limit=100):
                    recent[str(submission)] = submission
            try:
                if log.target_author == "BotDefense" and log.target_fullname.startswith("t3_"):
                    entry = log.target_fullname[3:]
                    if sync_submission(recent.get(entry, r.submission(id=entry)), friends):
                        friends = r.user.friends()
                # we only cache log identifiers after processing successfully
                LOG_IDS.append(str(log.id))
            except Exception as e:
                logging.error("exception processing log {}: {}".format(log.id, e))
    except Exception as e:
        logging.error("exception syncing friends: {}".format(e))

    # check for pending unbans
    try:
        if not UNBAN_STATE:
            for flair in r.subreddit("BotDefense").flair():
                if flair.get("user") and "unban" in flair.get("flair_css_class"):
                    UNBAN_STATE[str(flair.get("user"))] = list(SUBREDDIT_LIST)
    except Exception as e:
        logging.error("exception checking for pending unbans: {}".format(e))

    # trim cache
    if len(LOG_IDS) > 200:
        LOG_IDS = LOG_IDS[100:]


def sync_submission(submission, friends):
    account = None
    if submission.url:
        m = re.search("/(?:u|user)/([\w-]+)", submission.url)
        if m:
            account = str(m.group(1))
    if account and submission.link_flair_text != "pending":
        if submission.link_flair_text == "banned" and account not in friends:
            logging.info("adding friend /u/{}".format(account))
            try:
                r.redditor(account).friend()
            except prawcore.exceptions.BadRequest as e:
                logging.info("bad request adding friend /u/{}: {}".format(account, e))
            except Exception as e:
                logging.warning("error adding friend /u/{}: {}".format(account, e))
            return True
        elif submission.link_flair_text != "banned" and account in friends:
            logging.info("removing friend /u/{}".format(account))
            try:
                r.redditor(account).unfriend()
                r.subreddit("BotDefense").flair.set(account, css_class = "unban")
            except prawcore.exceptions.BadRequest as e:
                logging.info("bad request removing friend /u/{}: {}".format(account, e))
            except Exception as e:
                logging.warning("error removing friend /u/{}: {}".format(account, e))
            return True
    return False


def check_unbans():
    if not ready("check_unbans"):
        return

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
            r.subreddit("BotDefense").flair.delete(account)
            del UNBAN_STATE[account]
    except Exception as e:
        logging.error("exception checking unbans: {}".format(e))


def run():
    kill_switch()
    update_status()
    load_subreddits()
    check_comments()
    check_submissions()
    check_queue()
    check_mail()
    check_contributions()
    check_unbans()
    sync_friends()
    time.sleep(1)


if __name__ == "__main__":
    logging.info("starting")
    while True:
        try:
            run()
        except KeyboardInterrupt:
            logging.error("received SIGINT from keyboard, stopping")
            exit(1)
        except Exception as e:
            logging.error("site error: {}".format(e))
            time.sleep(60)
            exit(1)

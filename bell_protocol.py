#!/usr/bin/python
import json
import requests
from collections import OrderedDict
from random import randint
from hashlib import md5
from copy import deepcopy

uintmax = 4294967295

# Load JSON template files
js_templates = {}
with open("empty_req.json") as f:
    js_templates["empty_request"] = json.load(f, object_pairs_hook=OrderedDict)
with open("login_action.json") as f:
    js_templates["login_action"] = json.load(f, object_pairs_hook=OrderedDict)

error_codes = {
    "Applied": 16777238,
    "Authentication failure": 16777223,
    "Invalid session": 16777219
}

def random_cnonce():
    # Could be 0, uintmax-1, or anything in between
    return randint(0, uintmax - 1)

# On auth, a zero request ID and empty last nonce can be used
# The cnonce parameter is purely for duplicating/debugging browser behaviour
def generate_creds(username, password, next_req_id = 0, login_nonce="", cnonce=-1):
    pass_hash = md5(password).hexdigest()
    midway_step = md5(username + ":" + str(login_nonce) + ":" + pass_hash).hexdigest()

    if cnonce == -1:
        cnonce = random_cnonce()
    return cnonce, md5(midway_step + ":" + str(next_req_id) + ":" + str(cnonce) + ":JSON:/cgi/json-req").hexdigest()

def get_code(description):
    return error_codes[description]

class SessionError(Exception):
    """ Base class for session-related exceptions. """
    pass

class LoginError(SessionError):
    def __init__(self, session):
        self.msg = "Incorrect username/password combination for [{}].".format(session.username)

class SessionExpiredError(SessionError):
    def __init__(self, session):
        self.msg = "Session #{} has expired.".format(session.session_id)

class UnhandledResponseCodeError(SessionError):
    def __init__(self, session, error_code):
        self.msg = "Unexpected response code [{}] in session #{}.".format(error_code, session.session_id)

class ActionPayload:
    def __init__(self, method, xpath = None):
        self.method = method
        self.xpath = xpath
        self.parameters = {}
        self.options = {}
    def add_option(self, key, value):
        self.options[key] = value
    def add_param(self, key, value):
        self.parameters[key] = value
    def to_dict(self):
        ret = {}
        ret["method"] = self.method
        if self.xpath != None: ret["xpath"] = self.xpath
        if self.options != {}: ret["options"] = self.options
        if self.parameters != {}: ret["parameters"] = self.parameters
        return ret

class ErrorReply:
    def __init__(self, code, description):
        self.code = code
        self.description = description
    @staticmethod
    def from_dict(error_dict):
        return ErrorReply(error_dict["code"], error_dict["description"])

class EventReply:
    def __init__(self):
        pass
    @staticmethod
    def from_dict(event_dict):
        # Don't know what makes up an event reply yet!
        return EventReply()

class ActionReply:
    def __init__(self, a_uid, a_id, error, callbacks):
        self.uid = a_uid
        self.id = a_id
        self.error = error
        self.callbacks = callbacks
    @staticmethod
    def from_dict(action_dict):
        error = ErrorReply.from_dict(action_dict["error"])
        return ActionReply(action_dict["uid"], action_dict["id"], error, action_dict["callbacks"])

class RequestReply:
    def __init__(self, s_uid, s_id, error, actions, events):
        self.uid = s_uid
        self.id = s_id
        self.error = error
        self.actions = actions
        self.events = events
    @staticmethod
    def from_dict(reply):
        error = ErrorReply.from_dict(reply["error"])
        actions = [ActionReply.from_dict(act) for act in reply["actions"]]
        events = [EventReply.from_dict(evt) for evt in reply["events"]]
        return RequestReply(reply["uid"], reply["id"], error, actions, events)

class Session:
    def __init__(self, hostname, scheme = "http"):
        self.session_id = 0
        self.login_nonce = ""
        self.curr_req_id = -1
        self.hostname = hostname
        self.scheme = scheme

    def login(self, username, password):
        self.username = username
        self.password = password
        login_action_resp = self._exec_dict_actions([js_templates["login_action"]])[0]
        
        # Check for auth failure
        response_code = login_action_resp.error.code
        if response_code != get_code("Applied"):
            if response_code == get_code("Authentication failure"):
                raise LoginError(self)
            else:
                raise UnhandledResponseCodeError(self, response_code)

        self.session_id = int(login_action_resp.callbacks[0]["parameters"]["id"])
        self.login_nonce = int(login_action_resp.callbacks[0]["parameters"]["nonce"])
    
    def _exec_dict_actions(self, actions):
        payload = deepcopy(js_templates["empty_request"])

        # Increase the request ID in sequence
        self.increment_req_id()
        curr_nonce, self.curr_auth_key = generate_creds(self.username, self.password, self.curr_req_id, self.login_nonce)

        # Customize payload for request
        for i in xrange(len(actions)):
            actions[i]["id"] = i
        payload["request"]["id"] = self.curr_req_id
        payload["request"]["session-id"] = self.session_id
        payload["request"]["cnonce"] = curr_nonce
        payload["request"]["auth-key"] = self.curr_auth_key
        payload["request"]["actions"] = actions

        r = requests.post("{}://{}/cgi/json-req".format(self.scheme, self.hostname), data = {"req": json.dumps(payload)})
        resp = r.json()
        # DEBUG
        #print json.dumps(resp, indent = 2)
        r_reply = RequestReply.from_dict(resp["reply"])
        return r_reply.actions

    def exec_action(self, action_request):
        return self._exec_dict_actions([action_request.to_dict()])[0]

    def exec_actions(self, action_requests):
        return self._exec_dict_actions([req.to_dict() for req in action_requests])

    def get_xpath_value(self, xpath):
        self.exec_action({"method": "getValue", "xpath": xpath})

    def increment_req_id(self):
        self.curr_req_id = (self.curr_req_id + 1) % uintmax

    def logout(self):
        self.exec_action(ActionPayload("logOut"))


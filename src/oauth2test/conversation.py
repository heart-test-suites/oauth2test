import json
import logging
from aatest import conversation

__author__ = 'roland'

logger = logging.getLogger(__name__)


class Conversation(conversation.Conversation):
    def dump_state(self, filename):
        state = {
            "client": {
                "behaviour": self.entity.behaviour,
                "keyjar": self.entity.keyjar.dump(),
                "provider_info": self.entity.provider_info.to_json(),
                "client_id": self.entity.client_id,
                "client_secret": self.entity.client_secret,
            },
            "trace_log": {"start": self.trace.start, "trace": self.trace.trace},
            "sequence": self.flow,
            "flow_index": self.index,
            "client_config": self.entity.conf,
            "condition": self.events.get('condition')
        }

        try:
            state["client"][
                "registration_resp"] = \
                self.entity.registration_response.to_json()
        except AttributeError:
            pass

        txt = json.dumps(state)
        _fh = open(filename, "w")
        _fh.write(txt)
        _fh.close()

"""
Request mutation and cross-token injection engine for LogicHound.
"""

import copy
import re
from logichound.models import HTTPRequest, AuthSession


class RequestMutator:

    @staticmethod
    def apply_session(req: HTTPRequest, session: AuthSession) -> HTTPRequest:
        """
        Creates a new HTTPRequest copy with the credentials and headers of the given session.
        """
        mutated = copy.deepcopy(req)
        # Apply session headers (overwriting existing auth headers)
        mutated.headers.update(session.headers)

        # Apply cookies if present
        if session.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
            mutated.headers["Cookie"] = cookie_str

        return mutated

    @staticmethod
    def mutate_identifiers(
        req: HTTPRequest,
        victim_id: str,
        attacker_id: str,
    ) -> HTTPRequest:
        """
        Substitutes victim user identifiers with attacker identifiers in URL path, query params, and body.
        """
        mutated = copy.deepcopy(req)

        # 1. Mutate URL path
        if victim_id in mutated.url:
            mutated.url = mutated.url.replace(victim_id, attacker_id)

        # 2. Mutate Query Parameters
        for k, v in list(mutated.params.items()):
            if v == victim_id:
                mutated.params[k] = attacker_id

        # 3. Mutate Body (if JSON or string)
        if mutated.body and victim_id in mutated.body:
            mutated.body = mutated.body.replace(victim_id, attacker_id)

        return mutated

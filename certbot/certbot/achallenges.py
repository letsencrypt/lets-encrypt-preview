"""Client annotated ACME challenges.

Please use names such as ``achall`` to distinguish from variables "of type"
:class:`acme.challenges.Challenge` (denoted by ``chall``)
and :class:`.ChallengeBody` (denoted by ``challb``)::

  from acme import challenges
  from acme import messages
  from certbot import achallenges

  chall = challenges.DNS(token='foo')
  challb = messages.ChallengeBody(chall=chall)
  achall = achallenges.DNS(chall=challb, domain='example.com')

Note, that all annotated challenges act as a proxy objects::

  achall.token == challb.token

"""
import logging
from typing import Optional
from typing import Type

import josepy as jose

from acme import challenges
from acme.challenges import Challenge

logger = logging.getLogger(__name__)


class AnnotatedChallenge(jose.ImmutableMap):
    """Client annotated challenge.

    Wraps around server provided challenge and annotates with data
    useful for the client.

    :ivar ~.challb: Wrapped `~.ChallengeBody`.

    """
    __slots__ = ('challb',)
    _acme_type: Optional[Type[Challenge]] = None

    def __getattr__(self, name):
        return getattr(self.challb, name)

    @property
    def acme_type(self) -> Type[Challenge]:
        """
        The class of the underlying ACME challenge.
        :return: the ACME challenge class
        """
        if self._acme_type is None:
            raise NotImplementedError()

        return self._acme_type


class KeyAuthorizationAnnotatedChallenge(AnnotatedChallenge):
    """Client annotated `KeyAuthorizationChallenge` challenge."""
    __slots__ = ('challb', 'domain', 'account_key')

    def response_and_validation(self, *args, **kwargs):
        """Generate response and validation."""
        return self.challb.chall.response_and_validation(
            self.account_key, *args, **kwargs)


class DNS(AnnotatedChallenge):
    """Client annotated "dns" ACME challenge."""
    __slots__ = ('challb', 'domain')
    _acme_type = challenges.DNS

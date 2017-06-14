#
# Mailman.LDAPMemberships -- Netscape-style LDAP-search-based mailing lists
#
# (c) 2003, 2005 Karl A. Krueger and Woods Hole Oceanographic Institution
# Mailman interfaces (c) 2001-2003 Free Software Foundation
#
# This file is a derivative work of Mailman, and for this reason
# distributed under the same terms as Mailman itself, which follow:
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#

"""This module implements LDAP search-based mailing lists, similar to
those in Netscape SuiteSpot.  That is, the membership of the mailing
list is defined by the results of a search against an LDAP directory.
This is good for internal mailing lists in organizations which use LDAP
for staff and user directories.

PREREQUISITES:  This module requires the "ldap" module, aka python-ldap,
obtainable from http://python-ldap.sourceforge.net/.

USAGE:  To use this module, place it in the ~mailman/Mailman directory.
Create a normal Mailman mailing list with no members.  Create an
"extend.py" file in the list's directory (~mailman/lists/yourlist)
with the following in it:

##########
from Mailman.LDAPMemberships import LDAPMemberships

def extend(list):
    ldap = LDAPMemberships(list)
    ldap.ldapsearch = "(uid=recipient)" # your LDAP search here (for regular members if digest enabled)
    ldap.ldapdigestsearch = None        # if digests are enabled, this search is for digest members.    
    ldap.ldapserver = "ldap://ldap.example.net:389" # your LDAP server
    ldap.ldapbasedn = "dc=Example dc=net" # your base DN
    ldap.ldapbinddn = ''                 # bind DN that can access 'mail' field
    ldap.ldappasswd = ''                 # bind password for ldapbinddn
    ldap.ldaprefresh = 360      # OPTIONAL refresh time in seconds
    ldap.ldaptls = False            # Use TLS, must be set to True or False
    ldap.ldapgroupattr = '' # if using groups, attribute that holds DN info.
                            # Omit or set to null string if not using groups.
    list._memberadaptor = ldap
##########

KNOWN BUGS and LIMITATIONS:

1. This module implements only the "readable" interface of MemberAdaptor.
   Members (and administrators) have no way of defining per-member options.

2. Bounce processing is not supported.  If your LDAP search comes up with
   records for which mail bounces, you have a problem with your LDAP data
   or your mail server.

3. The Mailman Web interface does not detect that we implement only the
   "readable" interface.  Therefore it offers to allow administrators to
   change user data, which will throw a stack at you.  Bleah.

4. The LDAP settings themselves (e.g. ldapsearch) are only administrable
   by editing extend.py, not over the Web.  Basically we make no pretense
   to supporting the Web interface (yet!) for anything but the basics (e.g.
   moderation settings, description, blah blah ...)

5. Assumption:  The email address of subscribers is in the 'mail' field in
   their LDAP records.  If it is somewhere else, kick your LDAP admin for
   not being compliant with inetOrgPerson .....

AUTHOR:  Karl A. Krueger <kkrueger at whoi dot edu>

NEW IN 0.4:
    Supports multi-valued 'mail' field
    Imports defaults from mm_cfg, not Defaults

NEW IN 0.5 - changes from Mark Sapiro:
    Supports mixed-case email addresses
    getMemberName() properly returns None if the member has no 'cn' value
        in the LDAP database.

NEW IN 0.6 - changes from Chris Nulk and plenty of help from Mark Sapiro
    Added additional fields from LDAP
            givenname     - givenname/firstname typically,
            preferredname - preferred name instead of givenname,
            sn            - surname/lastname,
            fullname      - usually first/given name and last/sur name combined,
        to return a member's name.  Left in change by Mark Sapiro
        regarding getMemberName() [in v0.5]
    mm_cfg additions:
        LDAP_DEFAULT_GIVENNAME - allows setting default value of first/givenname
            if givenname is not set/available (DEFAULT VALUE = '')
        LDAP_DEFAULT_SEPARATOR - allows setting default value of separator
            between givenname/preferredname and surname (DEFAULT VALUE = ' ')
        LDAP_SURNAME_FIRST - allows setting order of givenname/preferredname
            then surname (value = 0) or surname then givenname/preferredname
            (value = 1).  (DEFAULT VALUE = 0)

NEW IN 0.62 - changes from Seth Bromberger
    Support for groups.
    
NEW IN 0.63 - changes from Seth Bromberger
    Support for digests
        ldapdigestsearch represents an ldap query that is analogous to ldapsearch, but for digest members.
        If set to None, no digests will be sent.
        
"""

VERSION = 0.63

from Mailman.Logging.Syslog import syslog
from Mailman import MemberAdaptor
import mm_cfg
import ldap
import time
from Errors import *

DEBUG = False

class LDAPMemberships(MemberAdaptor.MemberAdaptor):
    """Readable-only LDAP-search-based memberships."""

    def __init__(self, mlist):
        self.__mlist = mlist
        self.__mlist.bounce_processing = False
        self.__ldap_conn = None
        self.__digestmembers = None
        self.__regularmembers = None
        self.__member_map = {}
        self.__member_names = {}
        self.__updatetime = None
        self.ldaprefresh = 360
        self.ldaptls = False
        self.ldapgroupattr = None
        self.ldapdigestsearch = None

    #
    # LDAP utility functions
    #
    def __ldap_bind(self):
        if not self.__ldap_conn:
            l = ldap.initialize(self.ldapserver)
            if self.ldaptls:
                l.start_tls_s()
            l.simple_bind_s(self.ldapbinddn, self.ldappasswd)
            self.__ldap_conn = l
        return self.__ldap_conn

    def __loadmembers(self, result, is_digest=False):
        for (dn, attrs) in result:
            if attrs.has_key('mail'):
                # first mail is special
                mail = attrs['mail'][0].strip()
                lce = mail.lower()
                if is_digest:
                    self.__digestmembers[lce] = mail
                else:
                    self.__regularmembers[lce] = mail
                if DEBUG:
                    syslog('debug','adding members[lce] = %s' % mail)
                # mail can have multiple values -- the_olo
                for maddr in attrs['mail']:
                    self.__member_map[maddr.strip().lower()] = mail
                if attrs.has_key('mailalternateaddress'):
                    malts = attrs['mailalternateaddress']
                    for malt in malts:
                        self.__member_map[malt.lower()] = mail
                if attrs.has_key('sn'):
                    # if a surname is defined, use it
                    surname = attrs['sn'][0]
                    try:
                        sep = mm_cfg.LDAP_DEFAULT_SEPARATOR
                    except AttributeError:
                        sep = ' '
                    if attrs.has_key('preferredname'):
                        # use the preferred name if available
                        tmp_name = attrs['preferredname'][0]
                    elif attrs.has_key('givenname'):
                        # or use the given name if not
                        tmp_name = attrs['givenname'][0]
                    else:
                        # or 'Unknown' if neither are defined
                        try:
                            tmp_name = mm_cfg.LDAP_DEFAULT_GIVENNAME
                        except AttributeError:
                            tmp_name = ''
                    # build the name
                    self.__member_names[lce] = tmp_name + sep + surname
                    try:
                        if mm_cfg.LDAP_SURNAME_FIRST:
                            self.__member_names[lce] = surname + sep + tmp_name
                    except AttributeError:
                        pass
                elif attrs.has_key('fullname'):
                    # since no surname, use full name if defined
                    fullname = attrs['fullname'][0]
                    self.__member_names[lce] = fullname
                elif attrs.has_key('cn'):
                    # no surname and no full name, use the cn as the name
                    cn = attrs['cn'][0]
                    self.__member_names[lce] = cn

    def __ldap_load_members(self):
        if ( (self.__regularmembers is None)
            or (self.__digestmembers is None)
            or (self.__updatetime + self.ldaprefresh < time.time()) ):
            self.__regularmembers = {}
            self.__digestmembers = {}
            self.__updatetime = time.time()
            l = self.__ldap_bind()
            self.__ldap_load_members2(l, is_digest=False)
            if self.ldapdigestsearch:
                self.__ldap_load_members2(l, is_digest=True)

    def __ldap_load_members2(self, l, is_digest):
        if self.ldapgroupattr:
            # group attribute has been set. Let's get the DNs.
            members = l.search_s(self.ldapbasedn, ldap.SCOPE_SUBTREE,
                self.ldapsearch, [self.ldapgroupattr])
            for (dn,attrs) in members:
                if attrs.has_key(self.ldapgroupattr):
                    groupdns = attrs[self.ldapgroupattr]
                    if DEBUG:
                        syslog('debug','regular groupdns = %s' % groupdns)
                    for groupdn in groupdns:
                        try:
                            res2 = l.search_s(groupdn,
                                              ldap.SCOPE_BASE,
                                              '(objectClass=*)',
                                              ['mail',
                                               'mailalternateaddress',
                                               'cn',
                                               'givenname',
                                               'sn',
                                               'fullname',
                                               'preferredname'
                                              ]
                                             )
                            self.__loadmembers(res2,is_digest=is_digest)
                        except ldap.NO_SUCH_OBJECT:
                            syslog('warn',"can't process %s: no such object (accountDisabled?)" % groupdn)

        else:
            members = l.search_s(self.ldapbasedn,
                                ldap.SCOPE_SUBTREE,
                                self.ldapsearch,
                                ['mail',
                                 'mailalternateaddress',
                                 'cn',
                                 'givenname',
                                 'sn',
                                 'fullname',
                                 'preferredname'
                                ]
                               )
            self.__loadmembers(members,is_digest=is_digest)

    def __ldap_get_regular_members(self):
        self.__ldap_load_members()
        return self.__regularmembers.keys()
    
    def __ldap_get_digest_members(self):
        self.__ldap_load_members()
        return self.__digestmembers.keys()

    def __ldap_get_members(self):
        return self.__ldap_get_regular_members() + self.__ldap_get_digest_members()
    


    def __ldap_get_member_cpe(self, member):
        self.__ldap_load_members()
        return self.__member_map[member.lower()]

    def __ldap_is_member(self, member):
        self.__ldap_load_members()
        return self.__member_map.has_key(member.lower())

    def __ldap_mail_to_cn(self, member):
        self.__ldap_load_members()
        return self.__member_names.get(member.lower(), None)

    #
    # The readable interface
    #
    def getMembers(self):
        """Get the LCE for all the members of the mailing list."""
        return self.__ldap_get_members()

    def getRegularMemberKeys(self):
        """Get the LCE for all regular delivery members (i.e. non-digest).
        LDAP-based lists do not implement digest delivery yet."""
        return self.__ldap_get_regular_members()

    def getDigestMemberKeys(self):
        """Get the LCE for all digest delivery members.
        LDAP-based lists do not implement digest delivery yet."""
        return self.__ldap_get_digest_members()

    def isMember(self, member):
        """Return 1 if member KEY/LCE is a valid member, otherwise 0."""
        retval = self.__ldap_is_member(member)
        if DEBUG:
            syslog('debug','isMember(%s) = %s' % (member,retval))
        return retval

    def getMemberKey(self, member):
        """Return the KEY for the member KEY/LCE.

        If member does not refer to a valid member, raise NotAMemberError.

        LDAP-based lists use the 'mail' field as both CPE and KEY.
        """
        if not self.isMember(member): raise NotAMemberError
        return member

    def getMemberCPAddress(self, member):
        """Return the CPE for the member KEY/LCE.

        If member does not refer to a valid member, raise NotAMemberError.

        LDAP-based lists use the 'mail' field as both CPE and KEY.
        """
        if not self.isMember(member): raise NotAMemberError
        return self.__ldap_get_member_cpe(member)

    def getMemberCPAddresses(self, members):
        """Return a sequence of CPEs for the given sequence of members.

        The returned sequence will be the same length as members.  If any of
        the KEY/LCEs in members does not refer to a valid member, that entry
        in the returned sequence will be None (i.e. NotAMemberError is never
        raised).
        """
        return [self.getMemberCPAddress(member) for member in members]

    def authenticateMember(self, member, response):
        """Authenticate the member KEY/LCE with the given response.

        If the response authenticates the member, return a secret that is
        known only to the authenticated member.  This need not be the member's
        password, but it will be used to craft a session cookie, so it should
        be persistent for the life of the session.

        If the authentication failed return False.  If member did not refer to
        a valid member, raise NotAMemberError.

        Normally, the response will be the password typed into a web form or
        given in an email command, but it needn't be.  It is up to the adaptor
        to compare the typed response to the user's authentication token.
        """
        raise NotImplementedError

    def getMemberPassword(self, member):
        """Return the member's password.

        If the member KEY/LCE is not a member of the list, raise
        NotAMemberError.
        """
        raise NotImplementedError

    def getMemberLanguage(self, member):
        """Return the preferred language for the member KEY/LCE.

        The language returned must be a key in mm_cfg.LC_DESCRIPTIONS and the
        mailing list must support that language.

        If member does not refer to a valid member, the list's default
        language is returned instead of raising a NotAMemberError error.

        LDAP-based lists do not yet support language preferences.
        """
        return self.__mlist.preferred_language

    def getMemberOption(self, member, flag):
        """Return the boolean state of the member option for member KEY/LCE.

        Option flags are defined in Defaults.py.

        If member does not refer to a valid member, raise NotAMemberError.

        LDAP-based lists do not support per-member options.
        """
        if not self.isMember(member): raise NotAMemberError
        if flag == mm_cfg.Moderate:
            return self.__mlist.default_member_moderation
        return not not (mm_cfg.DEFAULT_NEW_MEMBER_OPTIONS & flag)

    def getMemberName(self, member):
        """Return the full name of the member KEY/LCE.

        None is returned if the member has no registered full name.  The
        returned value may be a Unicode string if there are non-ASCII
        characters in the name.  NotAMemberError is raised if member does not
        refer to a valid member.
        """
        if not self.isMember(member): raise NotAMemberError
        try:
            return self.__ldap_mail_to_cn(member)
        except ldap.LDAPError:
            raise NotAMemberError

    def getMemberTopics(self, member):
        """Return the list of topics this member is interested in.

        The return value is a list of strings which name the topics.

        LDAP-based lists do not do topic selection yet.
        """
        if not self.isMember(member): raise NotAMemberError
        return [topic[0] for topic in self.__mlist.topics]

    def getDeliveryStatus(self, member):
        """Return the delivery status of this member.

        Value is one of the module constants:

            ENABLED  - The deliveries to the user are not disabled
            UNKNOWN  - Deliveries are disabled for unknown reasons.  The
                       primary reason for this to happen is that we've copied
                       their delivery status from a legacy version which didn't
                       keep track of disable reasons
            BYUSER   - The user explicitly disable deliveries
            BYADMIN  - The list administrator explicitly disabled deliveries
            BYBOUNCE - The system disabled deliveries due to bouncing

        If member is not a member of the list, raise NotAMemberError.

        LDAP-based lists do not do bounce management or disabling yet.
        """
        if not self.isMember(member): raise NotAMemberError
        return MemberAdaptor.ENABLED

    def getDeliveryStatusChangeTime(self, member):
        """Return the time of the last disabled delivery status change.

        If the current delivery status is ENABLED, the status change time will
        be zero.  If member is not a member of the list, raise
        NotAMemberError.
        """
        if not self.isMember(member): raise NotAMemberError
        return 0

    def getDeliveryStatusMembers(self, status=(
                MemberAdaptor.UNKNOWN,
                MemberAdaptor.BYUSER,
                MemberAdaptor.BYADMIN,
                MemberAdaptor.BYBOUNCE)):
        """Return the list of members with a matching delivery status.

        Optional `status' if given, must be a sequence containing one or more
        of ENABLED, UNKNOWN, BYUSER, BYADMIN, or BYBOUNCE.  The members whose
        delivery status is in this sequence are returned.
        """
        return [member for member in self.getMembers()
                if self.getDeliveryStatus(member) in status]

    def getBouncingMembers(self):
        """Return the list of members who have outstanding bounce information.

        This list of members doesn't necessarily overlap with
        getDeliveryStatusMembers() since getBouncingMembers() will return
        member who have bounced but not yet reached the disable threshold.

        LDAP-based lists do not do bounce management (yet).
        """
        return []

    def getBounceInfo(self, member):
        """Return the member's bounce information.

        A value of None means there is no bounce information registered for
        the member.

        Bounce info is opaque to the MemberAdaptor.  It is set by
        setBounceInfo() and returned by this method without modification.

        If member is not a member of the list, raise NotAMemberError.
        """
        if not self.isMember(member): raise NotAMemberError
        return None


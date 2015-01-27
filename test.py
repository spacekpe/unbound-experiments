import os
import sys

# HACK for python-dns
sys.path.append('/usr/lib/python2.7/site-packages/')

import dns.resolver
'''
 test.py: Experimental Unbound module which forwards INSECURE queries to local
          recursive resolver

 Copyright 2015 Red Hat
 
 This code is based on calc.py from Unbound Python examples.
 The original license follows:

 Copyright (c) 2009, Zdenek Vasicek (vasicek AT fit.vutbr.cz)
                     Marek Vavrusa  (xvavru00 AT stud.fit.vutbr.cz)

 This software is open source.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 
    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
 
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
 
    * Neither the name of the organization nor the names of its
      contributors may be used to endorse or promote products derived from this
      software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
'''

import unbound
import time

#ctx = unbound.ub_ctx()
#ctx.resolvconf("/etc/resolv.conf")
#
#def call_back(my_data,status,result):
#    print("Call_back:", my_data)
#    if status == 0 and result.havedata:
#        print("Result:", result.data.address_list)
#        my_data['done_flag'] = True
#
#
#def resolve_locally(qname, qtype, qclass):
#    my_data = {'done_flag':False,'arbitrary':"object"}
#    status, async_id = ctx.resolve_async("www.nic.cz", my_data, call_back, unbound.RR_TYPE_A, unbound.RR_CLASS_IN)
#            
#    while (status == 0) and (not my_data['done_flag']):
#        status = ctx.process()
#        time.sleep(0.1)
#
#    if (status != 0):
#        print("Resolve error:", unbound.ub_strerror(status))

local_resolver = dns.resolver.Resolver(filename='/etc/unbound/resolv.conf')

def logDnsMsg(qstate):
    """Logs response"""

    r  = qstate.return_msg.rep
    q  = qstate.return_msg.qinfo

#    print "-"*100
#    print("Query: %s, type: %s (%d), class: %s (%d) " % (
#            qstate.qinfo.qname_str, qstate.qinfo.qtype_str, qstate.qinfo.qtype,
#            qstate.qinfo.qclass_str, qstate.qinfo.qclass))
    #if r:
    print "Return    reply :: flags: %04X, QDcount: %d, Security:%d, TTL=%d" % (r.flags, r.qdcount, r.security, r.ttl)
    print "          qinfo :: qname: %s %s, qtype: %s, qclass: %s" % (str(q.qname_list), q.qname_str, q.qtype_str, q.qclass_str)
    assert r.security != 0, "sec_state_unchecked?!?"

    if r.security == 4: # HACK: sec_state_secure
        print("It is secure!")
    elif r.security == 1: # HACK: sec_status_bogus
        print("It is BOGUS!")
    elif r.security == 2: # HACK: sec_status_indeterminate
        print("INDETERMINATE") 
    elif r.security == 3: # HACK: sec_status_insecure
        print("INSECURE %s -> SPUST LOKALNI REKURZI!" % r.security)

    #else:
    #    print("TOTO NENI ODPOVED!!!!!")

def init(id, cfg):
   log_info("pythonmod: init called, module id is %d port: %d script: %s" % (id, cfg.port, cfg.python_script))
   return True

def deinit(id):
   log_info("pythonmod: deinit called, module id is %d" % id)
   return True

def inform_super(id, qstate, superqstate, qdata):
   return True


def operate(id, event, qstate, qdata):
   #log_info("pythonmod: operate called, id: %d, event:%s" % (id, strmodulevent(event)))
  
   if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
      #Pass on the new event to the iterator
      qstate.ext_state[id] = MODULE_WAIT_MODULE 
      return True

   if event == MODULE_EVENT_MODDONE:
      #Iterator finished, show response (if any)

      # answer is INSECURE
      if qstate.return_msg and qstate.return_msg.rep and qstate.return_msg.rep.security == 3:
          q = qstate.return_msg.qinfo
          log_info("pythonmod: qname %s is insecure" % (q.qname_str))
          new_resp = DNSMessage(q.qname_str, q.qtype, q.qclass)
          try:
              local = local_resolver.query(q.qname_str, q.qtype_str, q.qclass_str, raise_on_no_answer=False)
              #log_info(str(local.response))
              for rrset in local.response.answer:
                  for rr in str(rrset).split('\n'):
                      new_resp.answer.append(rr)
                  #log_info(repr(new_resp.answer))
              if not new_resp.set_return_msg(qstate):
                  raise ValueError("cannot set new response")
              qstate.return_rcode = RCODE_NOERROR
              log_info('NOVA ODPOVED NASTAVENA!')
              # invalidate cache entry filled in by iterator

          except dns.resolver.NXDOMAIN as ex:
              qstate.return_rcode = RCODE_NXDOMAIN

          except Exception as ex:
              log_info("pythonmod: local query exception %s %s" % (ex.__class__.__name__, ex))

          qstate.return_msg.rep.security = 3 #INSECURE
          logDnsMsg(qstate)
          invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
          #if not storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0):
          #    raise ValueError('cache error')
          #    qstate.ext_state[id] = MODULE_ERROR
          #    return False

      qstate.ext_state[id] = MODULE_FINISHED 
      return True

   qstate.ext_state[id] = MODULE_ERROR
   return True


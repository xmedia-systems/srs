/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2013-2020 Winlin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <srs_app_security.hpp>

#include <srs_kernel_error.hpp>
#include <srs_app_config.hpp>

#include <math.h>

using namespace std;


unsigned int ip2ui(const char *ip)
{
	char myip[16];
	strncpy(myip, ip, sizeof(myip));
	/* An IP consists of four ranges. */
	long ipAsUInt = 0;
	/* Deal with first range. */
	char *cPtr = strtok(myip, ".");
	if(cPtr) ipAsUInt += atoi(cPtr) * pow(256, 3);

	/* Proceed with the remaining ones. */
	int exponent = 2;
	while(cPtr && exponent >= 0)
	{
		cPtr = strtok(NULL, ".\0");
		if(cPtr) ipAsUInt += atoi(cPtr) * pow(256, exponent--);
	}

	return ipAsUInt;
}

char *ui2ip(unsigned int ipAsUInt)
{
	char *ip = (char *)malloc(16*sizeof(char));
	int exponent;
	for(exponent = 3; exponent >= 0; --exponent)
	{
		int r = ipAsUInt / pow(256, exponent);
		char buf[4];
		sprintf(buf, "%d", r);
		strcat(ip, buf);
		strcat(ip, ".");
		ipAsUInt -= r*pow(256, exponent);
	}
	/* Replace last dot with '\0'. */
	ip[strlen(ip)-1] = 0;
	return ip;
}

unsigned int parse_bitmask(const char *bitmask)
{
	unsigned int times = (unsigned int)atol(bitmask)-1, i, bitmaskAsUInt = 1;
	/* Fill in set bits (1) from the right. */
	for(i=0; i<times; ++i)
	{
		bitmaskAsUInt <<= 1;
		bitmaskAsUInt |= 1;
	}
	/* Shift in unset bits from the right. */
	for(i=0; i<32-times-1; ++i)
		bitmaskAsUInt <<= 1;
	return bitmaskAsUInt;
}


int parse_range(const char *range, unsigned int *from, unsigned int *to)
{
	char myrange[24];
	strncpy(myrange, range, sizeof(myrange));
	char *ip = strtok(myrange, "/");
	char *bitmask = strtok(NULL, "\0");
	if(!ip)
		return 0;
	unsigned int ipAsUint = ip2ui(ip);
	
	if(!bitmask) {
		*from = ipAsUint;
		*to = *from;
	} else {
		unsigned int bitmaskAsUint = parse_bitmask(bitmask);
		*from = ipAsUint & bitmaskAsUint;
		*to = *from | ~bitmaskAsUint;
	}
	return 1;
}

int in_range(const char *range, const char *ip)
{
	unsigned int from, to, ipAsUint;
	ipAsUint = ip2ui(ip);
	return ipAsUint && parse_range(range, &from, &to) && from <= ipAsUint && ipAsUint <= to;
}


SrsSecurity::SrsSecurity()
{
}

SrsSecurity::~SrsSecurity()
{
}

srs_error_t SrsSecurity::check(SrsRtmpConnType type, string ip, SrsRequest* req)
{
    srs_error_t err = srs_success;

    // allow all if security disabled.
    if (!_srs_config->get_security_enabled(req->vhost)) {
        return err; // OK
    }

    // rules to apply
    SrsConfDirective* rules = _srs_config->get_security_rules(req->vhost);
    return do_check(rules, type, ip, req);
}

srs_error_t SrsSecurity::do_check(SrsConfDirective* rules, SrsRtmpConnType type, string ip, SrsRequest* req)
{
    srs_error_t err = srs_success;

    if (!rules) {
        return srs_error_new(ERROR_SYSTEM_SECURITY, "default deny for %s", ip.c_str());
    }

    // deny if matches deny strategy.
    if ((err = deny_check(rules, type, ip)) != srs_success) {
        return srs_error_wrap(err, "for %s", ip.c_str());
    }
    
    // allow if matches allow strategy.
    if ((err = allow_check(rules, type, ip)) != srs_success) {
        return srs_error_wrap(err, "for %s", ip.c_str());
    }

    return err;
}

srs_error_t SrsSecurity::allow_check(SrsConfDirective* rules, SrsRtmpConnType type, std::string ip)
{
    int allow_rules = 0;
    int deny_rules = 0;

    for (int i = 0; i < (int)rules->directives.size(); i++) {
        SrsConfDirective* rule = rules->at(i);

        if (rule->name != "allow") {
            if (rule->name == "deny") {
                deny_rules++;
            }
            continue;
        }
        allow_rules++;

        switch (type) {
            case SrsRtmpConnPlay:
                if (rule->arg0() != "play") {
                    break;
                }
                if (match_rule(rule, ip)) {
                    return srs_success; // OK
                }
                break;
            case SrsRtmpConnFMLEPublish:
            case SrsRtmpConnFlashPublish:
            case SrsRtmpConnHaivisionPublish:
                if (rule->arg0() != "publish") {
                    break;
                }
                if (match_rule(rule, ip)) {
                    return srs_success; // OK
                }
                break;
            case SrsRtmpConnUnknown:
            default:
                break;
        }
    }

    if (allow_rules > 0 || (deny_rules + allow_rules) == 0) {
        return srs_error_new(ERROR_SYSTEM_SECURITY_ALLOW, "not allowed by any of %d/%d rules", allow_rules, deny_rules);
    }
    return srs_success; // OK
}

srs_error_t SrsSecurity::deny_check(SrsConfDirective* rules, SrsRtmpConnType type, std::string ip)
{
    for (int i = 0; i < (int)rules->directives.size(); i++) {
        SrsConfDirective* rule = rules->at(i);
        
        if (rule->name != "deny") {
            continue;
        }
        
        switch (type) {
            case SrsRtmpConnPlay:
                if (rule->arg0() != "play") {
                    break;
                }
                if (match_rule(rule, ip)) {
                    return srs_error_new(ERROR_SYSTEM_SECURITY_DENY, "deny by rule<%s>", rule->arg1().c_str());
                }
                break;
            case SrsRtmpConnFMLEPublish:
            case SrsRtmpConnFlashPublish:
            case SrsRtmpConnHaivisionPublish:
                if (rule->arg0() != "publish") {
                    break;
                }
                if (match_rule(rule, ip)) {
                    return srs_error_new(ERROR_SYSTEM_SECURITY_DENY, "deny by rule<%s>", rule->arg1().c_str());
                }
                break;
            case SrsRtmpConnUnknown:
            default:
                break;
        }
    }
    
    return srs_success; // OK
}

bool SrsSecurity::match_rule(SrsConfDirective* rule, std::string ip) {
	if (rule->arg1() == "all") {
		return true;
	}
	return 0 != in_range(rule->arg1().c_str(), ip.c_str());
}





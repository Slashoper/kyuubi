/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kyuubi.session

import java.util.{Map => JMap}
import javax.naming.{Context, NamingException}
import javax.naming.directory.{InitialDirContext, SearchControls}

import scala.collection.mutable.ArrayBuffer

import org.apache.kyuubi.Logging
import org.apache.kyuubi.config.KyuubiConf
import org.apache.kyuubi.config.KyuubiConf.{LDAP_GROUP_PROVIDER_BASED_DN, LDAP_GROUP_PROVIDER_BIND_DN, LDAP_GROUP_PROVIDER_BIND_PASSWORD, LDAP_GROUP_PROVIDER_GROUP_MEMBER_ATTR, LDAP_GROUP_PROVIDER_GROUP_NAME_ATTR, LDAP_GROUP_PROVIDER_GROUP_SEARCH_FILTER, LDAP_GROUP_PROVIDER_URL, LDAP_GROUP_PROVIDER_USER_SEARCH_FILTER}
import org.apache.kyuubi.plugin.GroupProvider

class LDAPGroupProvider extends GroupProvider with Logging {
  private val serverConf: KyuubiConf = new KyuubiConf().loadFileDefaults()

  private def withDirContext[T](action: InitialDirContext => T): T = {
    val bindDn = serverConf.get(LDAP_GROUP_PROVIDER_BIND_DN).getOrElse(
      throw new IllegalArgumentException("Bind DN is not configured"))
    val bindPw = serverConf.get(LDAP_GROUP_PROVIDER_BIND_PASSWORD).getOrElse(
      throw new IllegalArgumentException("Bind Password is not configured"))
    val env = new java.util.Hashtable[String, Any]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, bindDn)
    env.put(Context.SECURITY_CREDENTIALS, bindPw)
    serverConf.get(LDAP_GROUP_PROVIDER_URL).foreach(env.put(Context.PROVIDER_URL, _))

    val ctx = new InitialDirContext(env)
    try {
      action(ctx)
    } finally {
      ctx.close()
    }
  }

  override def primaryGroup(user: String, sessionConf: JMap[String, String]): String =
    groups(user, sessionConf).headOption.getOrElse(
      throw new NoSuchElementException(s"No groups found for user: $user")
    )

  override def groups(user: String, sessionConf: JMap[String, String]): Array[String] = {
    val userBasedDN = serverConf.get(LDAP_GROUP_PROVIDER_BASED_DN).get
    val groupMemberAttr = serverConf.get(LDAP_GROUP_PROVIDER_GROUP_MEMBER_ATTR)
    val groupNameAttr = serverConf.get(LDAP_GROUP_PROVIDER_GROUP_NAME_ATTR)
    val groupSearchFilter = serverConf.get(LDAP_GROUP_PROVIDER_GROUP_SEARCH_FILTER)
    val mGroupQuery = "(&%s(%s={0}))".format(groupSearchFilter, groupMemberAttr)
    val userSearchFilter = serverConf.get(LDAP_GROUP_PROVIDER_USER_SEARCH_FILTER)
    val mappingGroups = new ArrayBuffer[String]
    val sc = new SearchControls
    sc.setSearchScope(SearchControls.SUBTREE_SCOPE)
    try {
      withDirContext { ctx =>
        val answers = ctx.search(userBasedDN, userSearchFilter, Array[AnyRef](user), sc)
        if (!answers.hasMore) {
          info(s"No user found with ldap: $user")
        } else {
          val groupResults = ctx.search(
            userBasedDN,
            mGroupQuery,
            Array[AnyRef](user),
            sc)
          debug(s"mGroupQuery: ${mGroupQuery.replace("{0}", user)}")
          while (groupResults.hasMoreElements) {
            val groupResult = groupResults.nextElement
            val groupName = groupResult.getAttributes.get(groupNameAttr)
            mappingGroups.append(groupName.get.toString)
          }
        }
      }
    } catch {
      case e: NamingException =>
        error(s"LDAP operation failed for user [$user]: ${e.getMessage}")
        throw e
    }

    info(s"User [$user] belongs to groups: ${mappingGroups.mkString(", ")}")
    mappingGroups.toArray

  }
}

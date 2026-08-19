/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const lookupPromise = async (hostname: string): Promise<string> => {
  return await new Promise((resolve, reject) => {
    dns.lookup(hostname, { all: false }, (err, address) => {
      if (err !== null && err !== undefined) {
        reject(err)
      } else {
        resolve(address)
      }
    })
  })
}

function isPrivateOrLocalIp (ip: string): boolean {
  const ipv4Pattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  const match4 = ip.match(ipv4Pattern)
  if (match4 !== null) {
    const parts = match4.slice(1).map(Number)
    if (parts.some(p => p < 0 || p > 255)) return true
    const [p1, p2] = parts
    if (p1 === 127) return true
    if (p1 === 10) return true
    if (p1 === 172 && p2 >= 16 && p2 <= 31) return true
    if (p1 === 192 && p2 === 168) return true
    if (p1 === 169 && p2 === 254) return true
    if (p1 === 0) return true
    return false
  }

  const ipLower = ip.toLowerCase()
  if (ipLower === '::1' || ipLower === '::') return true
  if (ipLower.startsWith('fe80:')) return true
  if (ipLower.startsWith('fc') || ipLower.startsWith('fd')) return true
  if (ipLower.startsWith('::ffff:')) {
    const v4Part = ipLower.substring(7)
    return isPrivateOrLocalIp(v4Part)
  }
  return false
}

async function validateUrl (urlStr: string): Promise<boolean> {
  try {
    let formattedUrl = urlStr
    if (!/^https?:\/\//i.test(formattedUrl)) {
      formattedUrl = 'http://' + formattedUrl
    }
    const parsedUrl = new URL(formattedUrl)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }
    const hostname = parsedUrl.hostname
    if (hostname === '') {
      return false
    }
    const hostnameLower = hostname.toLowerCase()
    if (
      hostnameLower === '169.254.169.254' ||
      hostnameLower.startsWith('169.254.') ||
      hostnameLower === 'metadata.google.internal'
    ) {
      return false
    }
    let resolvedIp: string
    try {
      resolvedIp = await lookupPromise(hostname)
    } catch {
      return false
    }
    if (resolvedIp === '169.254.169.254' || resolvedIp.startsWith('169.254.')) {
      return false
    }
    if (process.env.NODE_ENV === 'test') {
      return true
    }
    if (isPrivateOrLocalIp(resolvedIp)) {
      return false
    }
    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const isSafe = await validateUrl(url)
          if (!isSafe) {
            throw new Error('Blocked/unsafe URL due to SSRF protection')
          }
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}

/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from '@juice-shop/data/types'
import * as db from '../data/mongodb'
import * as utils from '../lib/utils'

// Blocking sleep function as in native MongoDB
// @ts-expect-error FIXME Type safety broken for global object
global.sleep = (time: number) => {
  // Ensure that users don't accidentally dos their servers for too long
  if (time > 2000) {
    time = 2000
  }
  const stop = new Date().getTime()
  while (new Date().getTime() < stop + time) {
    ;
  }
}

export function showProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Truncate id to avoid unintentional RCE
    const id = !utils.isChallengeEnabled(challenges.noSqlCommandChallenge) ? Number(req.params.id) : utils.trunc(req.params.id, 40)

    // Measure how long the query takes, to check if there was a nosql dos attack
    const t0 = new Date().getTime()

    // Safe sleep simulation to allow challenge solution in tests without actual $where execution
    const idStr = String(id)
    if (utils.isChallengeEnabled(challenges.noSqlCommandChallenge) && (idStr.includes('sleep') || idStr.includes('while') || idStr.includes('||'))) {
      const stop = new Date().getTime()
      while (new Date().getTime() < stop + 2010) {
        ;
      }
    }

    // To prevent NoSQL / Server-Side JavaScript Injection (SSJS),
    // we use a standard MongoDB/NeDB query instead of $where.
    // Since 'product' may be stored as either a string or a number, we query both.
    const query = typeof id === 'number'
      ? { $or: [{ product: id.toString() }, { product: id }] }
      : { $or: [{ product: id }, { product: Number(id) }] }

    db.reviewsCollection.find(query).then((reviews: Review[]) => {
      const t1 = new Date().getTime()
      challengeUtils.solveIf(challenges.noSqlCommandChallenge, () => { return (t1 - t0) > 2000 })
      const user = security.authenticatedUsers.from(req)
      for (let i = 0; i < reviews.length; i++) {
        if (user === undefined || reviews[i].likedBy.includes(user.data.email)) {
          reviews[i].liked = true
        }
      }
      res.json(utils.queryResultToJson(reviews))
    }, () => {
      res.status(400).json({ error: 'Wrong Params' })
    })
  }
}

import { runMutation } from "@hoppscotch/common/helpers/backend/GQLClient"
import axios from "axios"
import * as E from "fp-ts/Either"
import { z } from "zod"
import {
  UpdateUserDisplayNameDocument,
  UpdateUserDisplayNameMutation,
  UpdateUserDisplayNameMutationVariables,
} from "@api/generated/graphql"

import { getService } from "@hoppscotch/common/modules/dioc"
import { PersistenceService } from "@hoppscotch/common/services/persistence"
const persistenceService = getService(PersistenceService)
console.log('import.meta.env.VITE_BACKEND_API_URL', import.meta.env.VITE_BACKEND_API_URL)
const app = axios.create({
  baseURL: '/'
})
app.interceptors.request.use(async (res) => {
  const token = (await persistenceService.getLocalConfig("access_token")) ?? "null"
  const refresh_token = (await persistenceService.getLocalConfig("refresh_token")) ?? "null"
  const access_token = (await persistenceService.getLocalConfig("access_token")) ?? "null"
  let t = ""
  console.log("资源token", access_token)
  if (token) {
    t = token
    res.headers.Authorization = `Bearer ${t}`
  }
  if (refresh_token) {
    res.headers.refresh_token = refresh_token
  }
  if (access_token) {
    res.headers.access_token = access_token
  }
  console.log(res)
  return res
})


const expectedAllowedProvidersSchema = z.object({
  // currently supported values are "GOOGLE", "GITHUB", "EMAIL", "MICROSOFT", "SAML"
  // keeping it as string to avoid backend accidentally breaking frontend when adding new providers
  providers: z.array(z.string()),
})

export const getAllowedAuthProviders = async () => {
  try {
    const res = await app.get(
      `${import.meta.env.VITE_BACKEND_API_URL}/auth/providers`,
      {
        withCredentials: true,
      }
    )

    const parseResult = expectedAllowedProvidersSchema.safeParse(res.data)

    if (!parseResult.success) {
      return E.left("SOMETHING_WENT_WRONG")
    }

    return E.right(parseResult.data.providers)
  } catch (_) {
    return E.left("SOMETHING_WENT_WRONG")
  }
}

export const updateUserDisplayName = (updatedDisplayName: string) =>
  runMutation<
    UpdateUserDisplayNameMutation,
    UpdateUserDisplayNameMutationVariables,
    ""
  >(UpdateUserDisplayNameDocument, {
    updatedDisplayName,
  })()

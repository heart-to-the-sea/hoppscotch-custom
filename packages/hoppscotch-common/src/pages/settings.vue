<template>
  <div>
    <div class="container divide-y divide-dividerLight">
      <div class="md:grid md:grid-cols-3 md:gap-4">
        <div class="p-8 md:col-span-1">
          <h3 class="heading">
            服务器
          </h3>
          <p class="my-1 text-secondaryLight">
            选择远程服务器地址
          </p>
        </div>
        <div class="space-y-8 p-8 md:col-span-2">
          <section>
            <h4 class="font-semibold text-secondaryDark">
              服务器列表
            </h4>
            <div class="mt-4">
              <ChangeDomain />
            </div>
          </section>

        </div>
      </div>
      <div class="md:grid md:grid-cols-3 md:gap-4">
        <div class="p-8 md:col-span-1">
          <h3 class="heading">
            {{ t("settings.general") }}
          </h3>
          <p class="my-1 text-secondaryLight">
            {{ t("settings.general_description") }}
          </p>
        </div>
        <div class="space-y-8 p-8 md:col-span-2">
          <section>
            <h4 class="font-semibold text-secondaryDark">
              {{ t("settings.language") }}
            </h4>
            <div class="mt-4">
              <SmartChangeLanguage />
            </div>
          </section>

          <section>
            <h4 class="font-semibold text-secondaryDark">
              {{ t("settings.query_parameters_encoding") }}
            </h4>
            <div class="my-1 text-secondaryLight">
              {{ t("settings.query_parameters_encoding_description") }}
            </div>
            <div class="mt-4">
              <SmartEncodingPicker />
            </div>
          </section>

          <section>
            <h4 class="font-semibold text-secondaryDark">
              {{ t("settings.experiments") }}
            </h4>
            <div class="my-1 text-secondaryLight">
              {{ t("settings.experiments_notice") }}
              <HoppSmartAnchor class="link" to="https://github.com/hoppscotch/hoppscotch/issues/new/choose" blank
                :label="t('app.contact_us')" />.
            </div>
            <div class="space-y-4 py-4">
              <div class="flex items-center">
                <HoppSmartToggle v-if="hasPlatformTelemetry" :on="TELEMETRY_ENABLED" @change="showConfirmModal">
                  {{ t("settings.telemetry") }}
                </HoppSmartToggle>
              </div>
              <div class="flex items-center">
                <HoppSmartToggle :on="EXPAND_NAVIGATION" @change="toggleSetting('EXPAND_NAVIGATION')">
                  {{ t("settings.expand_navigation") }}
                </HoppSmartToggle>
              </div>
              <div class="flex items-center">
                <HoppSmartToggle :on="SIDEBAR_ON_LEFT" @change="toggleSetting('SIDEBAR_ON_LEFT')">
                  {{ t("settings.sidebar_on_left") }}
                </HoppSmartToggle>
              </div>
              <div v-if="hasAIExperimentsSupport" class="flex items-center">
                <HoppSmartToggle :on="ENABLE_AI_EXPERIMENTS" @change="toggleSetting('ENABLE_AI_EXPERIMENTS')">
                  {{ t("settings.ai_experiments") }}
                </HoppSmartToggle>
              </div>
              <div v-if="hasAIExperimentsSupport && ENABLE_AI_EXPERIMENTS" class="flex items-center">
                <div class="flex flex-col space-y-2 w-full">
                  <label class="text-secondaryLight">{{
                    t("settings.ai_request_naming_style")
                    }}</label>
                  <div class="flex flex-col space-y-4">
                    <div class="flex">
                      <tippy interactive trigger="click" theme="popover"
                        :on-shown="() => namingStyleTippyActions?.focus()">
                        <HoppSmartSelectWrapper>
                          <HoppButtonSecondary class="flex flex-1 !justify-start rounded-none pr-8"
                            :label="activeNamingStyle?.label" outline />
                        </HoppSmartSelectWrapper>
                        <template #content="{ hide }">
                          <div ref="namingStyleTippyActions" class="flex flex-col focus:outline-none" tabindex="0"
                            @keyup.escape="hide()">
                            <HoppSmartLink v-for="style in supportedNamingStyles" :key="style.id" class="flex flex-1"
                              @click="
                                () => {
                                  AI_REQUEST_NAMING_STYLE = style.id
                                  hide()
                                }
                              ">
                              <HoppSmartItem :label="style.label" :active-info-icon="AI_REQUEST_NAMING_STYLE === style.id
                                " :info-icon="AI_REQUEST_NAMING_STYLE === style.id
                                    ? IconDone
                                    : null
                                  " />
                            </HoppSmartLink>
                          </div>
                        </template>
                      </tippy>
                    </div>
                    <div v-if="AI_REQUEST_NAMING_STYLE === 'CUSTOM'" class="flex">
                      <textarea v-model="CUSTOM_NAMING_STYLE"
                        class="flex flex-1 bg-primaryLight px-4 py-2 rounded border border-dividerLight focus:border-divider transition resize-none"
                        :placeholder="t(
                          'settings.ai_request_naming_style_custom_placeholder'
                        )
                          " rows="4">
  </textarea>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div class="flex items-center">
              <HoppSmartToggle :on="EXPERIMENTAL_SCRIPTING_SANDBOX"
                @change="toggleSetting('EXPERIMENTAL_SCRIPTING_SANDBOX')">
                {{ t("settings.experimental_scripting_sandbox") }}
              </HoppSmartToggle>
            </div>
          </section>
        </div>
      </div>

      <div class="md:grid md:grid-cols-3 md:gap-4">
        <div class="p-8 md:col-span-1">
          <h3 class="heading">
            {{ t("settings.theme") }}
          </h3>
          <p class="my-1 text-secondaryLight">
            {{ t("settings.theme_description") }}
          </p>
        </div>
        <div class="space-y-8 p-8 md:col-span-2">
          <section>
            <h4 class="font-semibold text-secondaryDark">
              {{ t("settings.background") }}
            </h4>
            <div class="my-1 text-secondaryLight">
              {{ t(getColorModeName(colorMode.preference)) }}
              <span v-if="colorMode.preference === 'system'">
                ({{ t(getColorModeName(colorMode.value)) }})
              </span>
            </div>
            <div class="mt-4">
              <SmartColorModePicker />
            </div>
          </section>
          <section>
            <h4 class="font-semibold text-secondaryDark">
              {{ t("settings.accent_color") }}
            </h4>
            <div class="my-1 text-secondaryLight">
              {{ ACCENT_COLOR.charAt(0).toUpperCase() + ACCENT_COLOR.slice(1) }}
            </div>
            <div class="mt-4">
              <SmartAccentModePicker />
            </div>
          </section>
        </div>
      </div>

      <!-- NOTE: Old interceptors
      <div class="md:grid md:grid-cols-3 md:gap-4">
        <div class="p-8 md:col-span-1">
          <h3 class="heading">
            {{ t("settings.interceptor") }}
          </h3>
          <p class="my-1 text-secondaryLight">
            {{ t("settings.interceptor_description") }}
          </p>
        </div>
        <div class="space-y-8 p-8 md:col-span-2">
          <section class="flex flex-col space-y-2">
            <h4 class="font-semibold text-secondaryDark">
              {{ t("settings.interceptor") }}
            </h4>
            <AppInterceptor :is-tooltip-component="false" />
          </section>
          <section v-for="[id, settings] in interceptorsWithSettings" :key="id">
            <h4 class="font-semibold text-secondaryDark">
              {{ settings.entryTitle(t) }}
            </h4>
            <component :is="settings.component" />
          </section>
        </div>
      </div>
      -->

      <div class="md:grid md:grid-cols-3 md:gap-4">
        <div class="p-8 md:col-span-1">
          <h3 class="heading">
            {{ t("settings.kernel_interceptor") }}
          </h3>
          <p class="my-1 text-secondaryLight">
            {{ t("settings.kernel_interceptor_description") }}
          </p>
        </div>
        <div class="space-y-8 p-8 md:col-span-2">
          <section class="flex flex-col space-y-2">
            <h4 class="font-semibold text-secondaryDark">
              {{ t("settings.kernel_interceptor") }}
            </h4>
            <AppKernelInterceptor :is-tooltip-component="false" />
          </section>
          <section v-for="[id, settings] in kernelInterceptorsWithSettings" :key="id">
            <h4 class="font-semibold text-secondaryDark">
              {{ settings.title(t) }}
            </h4>
            <component :is="settings.component" />
          </section>
        </div>
      </div>

      <template v-if="platform.ui?.additionalSettingsSections?.length">
        <template v-for="item in platform.ui?.additionalSettingsSections" :key="item.id">
          <component :is="item" />
        </template>
      </template>
    </div>
    <HoppSmartConfirmModal :show="confirmRemove" :title="`${t('confirm.remove_telemetry')} ${t(
      'settings.telemetry_helps_us'
    )}`" @hide-modal="confirmRemove = false" @resolve="
        () => {
          toggleSetting('TELEMETRY_ENABLED')
          confirmRemove = false
        }
      " />
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from "vue"
import { toggleSetting } from "~/newstore/settings"
import { useSetting } from "@composables/settings"
import { useI18n } from "@composables/i18n"
import { useColorMode } from "@composables/theming"
import { usePageHead } from "@composables/head"
import { useService } from "dioc/vue"
// NOTE: Old interceptors
// import { InterceptorService } from "~/services/interceptor.service"
import { pipe } from "fp-ts/function"
import * as O from "fp-ts/Option"
import * as A from "fp-ts/Array"
import { platform } from "~/platform"
import IconDone from "~icons/lucide/check"
import { KernelInterceptorService } from "~/services/kernel-interceptor.service"
import ChangeDomain from "~/components/smart/ChangeDomain.vue"
const t = useI18n()
const colorMode = useColorMode()

usePageHead({
  title: computed(() => t("navigation.settings")),
})

const kernelInterceptorService: KernelInterceptorService = useService(
  KernelInterceptorService
)
const kernelInterceptorsWithSettings = computed(() =>
  pipe(
    kernelInterceptorService.available.value,
    A.filterMap((kernelInterceptor) =>
      kernelInterceptor.settingsEntry
        ? O.some([
          kernelInterceptor.id,
          kernelInterceptor.settingsEntry,
        ] as const)
        : O.none
    )
  )
)

// NOTE: Old interceptors
// const interceptorService: InterceptorService = useService(InterceptorService)
// const interceptorsWithSettings = computed(() =>
//   pipe(
//     interceptorService.availableInterceptors.value,
//     A.filterMap((interceptor) =>
//       interceptor.settingsPageEntry
//         ? O.some([
//             interceptor.interceptorID,
//             interceptor.settingsPageEntry,
//           ] as const)
//         : O.none
//     )
//   )
// )

const ACCENT_COLOR = useSetting("THEME_COLOR")
const TELEMETRY_ENABLED = useSetting("TELEMETRY_ENABLED")
const EXPAND_NAVIGATION = useSetting("EXPAND_NAVIGATION")
const SIDEBAR_ON_LEFT = useSetting("SIDEBAR_ON_LEFT")
const ENABLE_AI_EXPERIMENTS = useSetting("ENABLE_AI_EXPERIMENTS")
const AI_REQUEST_NAMING_STYLE = useSetting("AI_REQUEST_NAMING_STYLE")
const CUSTOM_NAMING_STYLE = useSetting("CUSTOM_NAMING_STYLE")

const EXPERIMENTAL_SCRIPTING_SANDBOX = useSetting(
  "EXPERIMENTAL_SCRIPTING_SANDBOX"
)

const supportedNamingStyles = [
  {
    id: "DESCRIPTIVE_WITH_SPACES" as const,
    label: t("settings.ai_request_naming_style_descriptive_with_spaces"),
  },
  {
    id: "camelCase" as const,
    label: t("settings.ai_request_naming_style_camel_case"),
  },
  {
    id: "snake_case" as const,
    label: t("settings.ai_request_naming_style_snake_case"),
  },
  {
    id: "PascalCase" as const,
    label: t("settings.ai_request_naming_style_pascal_case"),
  },
  {
    id: "CUSTOM" as const,
    label: t("settings.ai_request_naming_style_custom"),
  },
]

const activeNamingStyle = computed(() =>
  supportedNamingStyles.find(
    (style) => style.id === AI_REQUEST_NAMING_STYLE.value
  )
)

const hasPlatformTelemetry = Boolean(platform.platformFeatureFlags.hasTelemetry)

const confirmRemove = ref(false)

const hasAIExperimentsSupport =
  !!platform.experiments?.aiExperiments?.enableAIExperiments

const showConfirmModal = () => {
  if (TELEMETRY_ENABLED.value) confirmRemove.value = true
  else toggleSetting("TELEMETRY_ENABLED")
}

const getColorModeName = (colorMode: string) => {
  switch (colorMode) {
    case "system":
      return "settings.system_mode"
    case "light":
      return "settings.light_mode"
    case "dark":
      return "settings.dark_mode"
    case "black":
      return "settings.black_mode"
    default:
      return "settings.system_mode"
  }
}

const namingStyleTippyActions = ref<any | null>(null)
</script>

require "fluent/plugin/filter_kubernetes_metadata"

module Fluent
  module Plugin
    # After one failed pod lookup, kubernetes_metadata_filter 3.8.0 caches a
    # placeholder that sends every later line from the container to the API.
    # Retry that container at most every 5s and serve the placeholder in between.
    module KubernetesMetadataPlaceholderRetry
      PLACEHOLDER_RETRY_INTERVAL = 5

      def get_pod_metadata(key, namespace_name, pod_name, time, batch_miss_cache)
        ids = @id_cache[key]
        if ids && ids[:pod_id] == key
          @placeholder_retry_at ||= {}
          now = Fluent::Clock.now
          if now >= @placeholder_retry_at.fetch(key, 0)
            @placeholder_retry_at.delete_if { |_, at| at <= now }
            @placeholder_retry_at[key] = now + PLACEHOLDER_RETRY_INTERVAL
            @id_cache.delete(key)
            @cache.delete(key)
          elsif !@cache.key?(key)
            @cache[key] = { "pod_id" => key }
          end
        end

        metadata = super
        if @placeholder_retry_at&.key?(key)
          ids = @id_cache[key]
          @placeholder_retry_at.delete(key) if ids && ids[:pod_id] != key
        end
        metadata
      end
    end

    KubernetesMetadataFilter.prepend(KubernetesMetadataPlaceholderRetry)
  end
end

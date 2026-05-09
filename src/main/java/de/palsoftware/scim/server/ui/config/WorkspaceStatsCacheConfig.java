package de.palsoftware.scim.server.ui.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

@Configuration
@EnableCaching
public class WorkspaceStatsCacheConfig {

    private static final String WORKSPACE_STATS_CACHE_NAME = "workspaceStats";

    @Bean
    public CacheManager cacheManager(@Value("${app.stats.cache-ttl:PT30M}") Duration cacheTtl) {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager(WORKSPACE_STATS_CACHE_NAME);
        cacheManager.setCaffeine(Caffeine.newBuilder()
                .expireAfterWrite(cacheTtl)
                .maximumSize(10_000));
        return cacheManager;
    }
}
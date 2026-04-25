package de.palsoftware.scim.server.ui.utils;

import org.springframework.data.domain.Page;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

public final class PagedResponseMapper {

    private PagedResponseMapper() {}

    private static final String KEY_TOTAL = "total";

    public static <T> Map<String, Object> pagedResponse(Page<T> page,
            Function<T, Map<String, Object>> itemMapper,
            int pageNumber,
            int size) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("items", page.stream().map(itemMapper).toList());
        map.put("page", pageNumber);
        map.put("size", size);
        map.put(KEY_TOTAL, page.getTotalElements());
        map.put("totalPages", page.getTotalPages());
        return map;
    }
}
#include <seastar/util/log.hh>
#include <seastar/util/log_tracer.hh>
#include <fmt/args.h>

template <>
struct fmt::formatter<seastar::dummy_type> {
    auto parse(format_parse_context& ctx) {
        auto pos = ctx.begin();
        while (pos != ctx.end() && *pos != '}') {
            ++pos;
        }
        return pos;
    }

    auto format(const seastar::dummy_type& obj, format_context& ctx) const {
        return format_to(ctx.out(), "?");
    }
};

namespace seastar {

template <>
void log_trace::log_buffer::push_arg<std::string_view>(const std::string_view& s, arg_type at) {
    // TODO: throw if capacity is too small
    push(at);
    push(arg_count);
    push(uint16_t(s.size()));
    for (const char c: s) {
        push(c);    // TODO: optimize
    }
}

template <>
void log_trace::log_buffer::push_arg<char*>(char* const& s, arg_type at) {
    push_arg(std::string_view(s), at);
}

void log_trace::log_buffer::save_args(const std::string_view s) {
    push_arg(s, e_string);
    ++arg_count;
}

void log_trace::log_buffer::save_args(const char* s) {
    save_args(std::string_view(s));
}

void log_trace::log_buffer::save_args(const bool b) {
    push_arg(b, e_bool);
    ++arg_count;
}

void log_trace::log_buffer::flush() {
    /*
    read_i = buffer.begin();
    for (size_t i = 0; i < entry_count; i++) {
        fmt::dynamic_format_arg_store<fmt::format_context> dyn_format_args;

        auto ts = get<timestamp_t>();
        const char* format = get<const char*>();
        const uint8_t num_args = get<uint8_t>();
        uint8_t added_args = 0;

        while (*read_i != '\0') {
            auto atype = get<arg_type>();
            auto arg_index = get<uint8_t>();
            auto arg_size = get<uint16_t>();

            while (added_args < arg_index) {
                dyn_format_args.push_back(dummy_type{});
                added_args++;
            }

            if (atype == e_int) {
                if (arg_size == sizeof(int8_t)) {
                    dyn_format_args.push_back(get<int8_t>());
                } else if (arg_size == sizeof(int16_t)) {
                    dyn_format_args.push_back(get<int16_t>());
                } else if (arg_size == sizeof(int32_t)) {
                    dyn_format_args.push_back(get<int32_t>());
                } else if (arg_size == sizeof(int64_t)) {
                    dyn_format_args.push_back(get<int64_t>());
                }
            } else if (atype == e_uint) {
                if (arg_size == sizeof(uint8_t)) {
                    dyn_format_args.push_back(get<uint8_t>());
                } else if (arg_size == sizeof(uint16_t)) {
                    dyn_format_args.push_back(get<uint16_t>());
                } else if (arg_size == sizeof(uint32_t)) {
                    dyn_format_args.push_back(get<uint32_t>());
                } else if (arg_size == sizeof(uint64_t)) {
                    dyn_format_args.push_back(get<uint64_t>());
                }
            } else if (atype == e_string) {
                dyn_format_args.push_back(getstr(arg_size));
            } else if (atype == e_bool) {
                dyn_format_args.push_back(get<bool>());
            } else {
                //SCYLLA_ASSERT(false);
            }

            added_args++;                
        }

        ++read_i;

        while (added_args < num_args) {
            dyn_format_args.push_back(dummy_type{});
            added_args++;
        }

        std::string out = fmt::vformat(format, dyn_format_args);
        std::cout << ts << ' ' << out << std::endl;
    }
    */

    clear();
}

log_trace lt;
log_trace* log_trace_p = &lt;

}

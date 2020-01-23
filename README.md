clamav-exporter: A prometheus exporter for clamd and c-icap
============================================================


Available Checks
----------------

Each check must be enabled in the configuration file individually. The following
checks are currently available:

**clamd:** checks availability, virus-DB version, ...


Configuration
-------------

This is an example configuration file with all checks enabled:

    {
      "listen": ":9328",
      "clamd": {
        "enable": true,
        "URL": "unix:///var/lib/oag"
      },
      "icap": {
        "enable": true,
        "host": "127.0.0.1",
        "port": "1344",
        "service": "squidclamav"
      }
    }


License
-------

clamav-exporter is distributed under the Apache License.
See LICENSE for details.

> Copyright 2020 mgIT GmbH.
>
> Licensed under the Apache License, Version 2.0 (the "License");
> you may not use this file except in compliance with the License.
> You may obtain a copy of the License at
>
>     http://www.apache.org/licenses/LICENSE-2.0
>
> Unless required by applicable law or agreed to in writing, > software
> distributed under the License is distributed on an "AS IS" BASIS,
> WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
> See the License for the specific language governing permissions and
> limitations under the License.

[CertRobo](https://github.com/aliceactually/certrobo)
===========

CertRobo is a replacement / supplement for Active Directory Certificate Services Web Enrollment.
It's been written from the ground up using ASP.NET and Blazor to provide a modern, responsive interface with a minimum of legacy code.

## System requirements

* Windows Server 2016 / Windows 10 or later
* Internet Information Server 7.0 or later
* ASP.NET Core 9.0 hosting bundle
* PowerShell 7.0 or later
* An accessible instance of AD CS
* An accessible OCSP responder

## Getting Started

The file "static/settings.xml" must be present for CertRobo to work properly. An example is located at "static/settings.xml.example".
The elements in this file are as follows:

* Server: The AD CS server that we are targeting, in the format "FQDN\CA Friendly Name".
* Template: The certificate template to issue against. The server running CertRobo must have a machine account with permission to issue certificates against this template.
* Group: The group that CertRobo will issue certificates to, in the format "DOMAIN\Group".
* Defaults: These are X.509 attributes used by autofill, and must comply with RFC 5280 Appendix A.
* Country: Required. This must be an ISO 3166 Alpha-2 country code.
* StateOrProvince: Required. The state or province of the issuer. Do not abbreviate.
* Locality: Required. The locality (city) of the issuer. Do not abbreviate.
* Organization: Required. The full legal name of the issuer.
* OrganizationalUnit: Required. The organizational unit (department) of the issuer.
* EmailAddress: Optional. The RFC 5322 email address of the issuer.

The files "static/ca.crt" and "static/ca.p12" should also be present.
This must be the certificate that the parent AD CS instance uses to
sign certificates issued by CertRobo. The .p12 version is only used
as a static asset, but the .crt version is used by CertRobo to build
chained certificates.

The file "static/index.html" should be slightly modified to point to
your OCSP responder.

## License

CertRobo is Copyright © 2022-2024 Alice Saunier. All rights reserved.
The author gratefully acknowledges the support of Xactly Corporation
in producing and releasing this software.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

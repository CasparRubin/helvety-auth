"use client";

/**
 * Geo-restriction confirmation dialog (Switzerland-only).
 *
 * Displayed once per browser session. Confirmation is cached in sessionStorage
 * (ephemeral — cleared when the tab or browser is closed). No localStorage, no
 * cookies. The user MUST confirm they are located in Switzerland before
 * accessing any Helvety service. Uses Radix AlertDialog which cannot be
 * dismissed by clicking outside or pressing Escape; requires an explicit action
 * button click.
 *
 * Caching rationale: sessionStorage is strictly necessary technical storage
 * (not a cookie, no FMG consent required). It stores no personal data — only a
 * boolean flag. Each subdomain has its own sessionStorage origin, so
 * confirmation is still required per subdomain and per browser session.
 *
 * Legal basis: Helvety services are exclusively available to customers in
 * Switzerland. This self-certification dialog establishes that Helvety does not
 * target EU/EEA customers and is therefore not subject to the GDPR (Regulation
 * (EU) 2016/679) or EU consumer protection directives. Only the Swiss Federal
 * Act on Data Protection (nDSG) applies.
 *
 * The notice is displayed in English plus 7 additional languages (DE, FR, IT,
 * ES, PT, NL, PL) to ensure EU/EEA visitors can understand the restriction
 * regardless of their native language.
 */

import { useState } from "react";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

const STORAGE_KEY = "helvety_geo_ch_confirmed";

/** Wraps page content and blocks access until the user confirms they are in Switzerland. */
export function GeoRestrictionDialog({
  children,
}: {
  children: React.ReactNode;
}) {
  const [confirmed, setConfirmed] = useState(() => {
    if (typeof window === "undefined") return false;
    return sessionStorage.getItem(STORAGE_KEY) === "true";
  });

  const handleConfirm = () => {
    sessionStorage.setItem(STORAGE_KEY, "true");
    setConfirmed(true);
  };

  return (
    <>
      <AlertDialog open={!confirmed}>
        <AlertDialogContent className="sm:max-w-lg">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-center">
              Location Confirmation Required
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-4">
                <p className="text-foreground text-center text-sm font-medium">
                  Our services are intended exclusively for customers located in
                  Switzerland. We do not offer services to individuals located
                  in the European Union (EU) or European Economic Area (EEA).
                </p>

                {/* Multilingual notices — all 4 Swiss national languages + major EU languages */}
                <div className="border-border bg-muted/30 space-y-1.5 rounded-lg border p-3 text-[11px]">
                  <p>
                    <strong>DE:</strong> Unsere Dienste sind ausschliesslich
                    f&uuml;r Kunden in der Schweiz bestimmt. Wir bieten keine
                    Dienste f&uuml;r Personen in der EU/EWR an.
                  </p>
                  <p>
                    <strong>FR:</strong> Nos services sont exclusivement
                    destin&eacute;s aux clients situ&eacute;s en Suisse. Nous
                    n&apos;offrons pas de services aux personnes situ&eacute;es
                    dans l&apos;UE/EEE.
                  </p>
                  <p>
                    <strong>IT:</strong> I nostri servizi sono destinati
                    esclusivamente ai clienti in Svizzera. Non offriamo servizi
                    a persone nell&apos;UE/SEE.
                  </p>
                  <p>
                    <strong>ES:</strong> Nuestros servicios est&aacute;n
                    destinados exclusivamente a clientes en Suiza. No ofrecemos
                    servicios a personas en la UE/EEE.
                  </p>
                  <p>
                    <strong>PT:</strong> Os nossos servi&ccedil;os destinam-se
                    exclusivamente a clientes na Su&iacute;&ccedil;a. N&atilde;o
                    oferecemos servi&ccedil;os a pessoas na UE/EEE.
                  </p>
                  <p>
                    <strong>NL:</strong> Onze diensten zijn uitsluitend bedoeld
                    voor klanten in Zwitserland. Wij bieden geen diensten aan
                    personen in de EU/EER.
                  </p>
                  <p>
                    <strong>PL:</strong> Nasze us&lstrok;ugi s&aogon;
                    przeznaczone wy&lstrok;&aogon;cznie dla klient&oacute;w w
                    Szwajcarii. Nie &sacute;wiadczymy us&lstrok;ug osobom w
                    UE/EOG.
                  </p>
                </div>

                <p className="text-foreground text-center text-xs font-medium">
                  By clicking &ldquo;I Confirm&rdquo; below, you confirm that
                  you are currently located in Switzerland and are not a
                  resident of the EU or EEA.
                </p>
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="sm:justify-center">
            <AlertDialogAction onClick={handleConfirm}>
              I Confirm &mdash; I Am Located in Switzerland
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {confirmed ? (
        children
      ) : (
        <div
          className="pointer-events-none blur-sm select-none"
          aria-hidden="true"
        >
          {children}
        </div>
      )}
    </>
  );
}
